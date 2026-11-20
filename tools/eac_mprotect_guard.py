#!/usr/bin/env python3
"""Launch the game and patch EAC without ptrace or build-specific offsets.

The tool locates two native-code anchors in EAC's live memfd image:

* the mprotect wrapper used before the game-local DLL header is erased;
* the helper immediately preceding the violation-registration entry point.

It redirects the wrapper to a conditional in-module stub and short-circuits the
derived violation entry. If any signature is missing or ambiguous, nothing is
patched and the tool exits with an error.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


MPROTECT_SIGNATURE = bytes.fromhex(
    "f30f1efa554889e5534881ec8800000048897d884889758089957cffffff"
    "48898d70ffffff64488b042528000000488945e831c048837d88007407"
    "48837d8000750abb00000000e996000000"
)

# This helper builds the platform-specific executable path list. It remained
# byte-identical across the two EAC builds used to derive and verify the
# detector, while its image-relative address changed.
#REPORT_HELPER_SIGNATURE = bytes.fromhex(
#    "f30f1efa41574156415541544989f455534889fb4883ec48"
#    "64488b042528000000488944243831c04c8d6c24184c8d7424204c89ef"
#)
REPORT_HELPER_SIGNATURE = bytes.fromhex(
    "41574156415541544989f4554889fd534883ec48"
    "64488b042528000000488944243831c0"
)
REPORT_HELPER_EPILOGUE_PREFIX = bytes.fromhex(
    "488b44243864482b0425280000007405e8"
)
REPORT_HELPER_EPILOGUE_SUFFIX = bytes.fromhex(
    "4883c4485b5d415c415d415e415fc3"
)
NATIVE_REPORT_SIGNATURE = bytes.fromhex(
    "f30f1efa41574156415541544189f4554889d5"
)

WRAPPER_HEAD_SIZE = 16
PATCH_RETURN_ZERO = bytes.fromhex("31c0c3")
MIN_CODE_CAVE_SIZE = 128
MAX_MODULE_SIZE = 0x1000000


@dataclass(frozen=True)
class Mapping:
    begin: int
    end: int
    permissions: str
    offset: int
    path: str


class DetectionError(RuntimeError):
    pass


class ProcessMemory:
    def __init__(self, pid: int):
        self.fd = os.open(f"/proc/{pid}/mem", os.O_RDWR)

    def close(self) -> None:
        os.close(self.fd)

    def read(self, address: int, size: int) -> bytes:
        data = os.pread(self.fd, size, address)
        if len(data) != size:
            raise OSError(f"short read at {address:#x}: {len(data)} of {size} bytes")
        return data

    def write(self, address: int, data: bytes) -> None:
        written = os.pwrite(self.fd, data, address)
        if written != len(data):
            raise OSError(f"short write at {address:#x}: {written} of {len(data)} bytes")


PROLOGUE_STARTS = (
    bytes.fromhex("f30f1efa4157"),
    bytes.fromhex("4157415641554154"),
    bytes.fromhex("f30f1efa554889e5"),
    bytes.fromhex("554889e5"),
)


def _valid_violation_entry_at(
    memory: ProcessMemory,
    address: int,
    executable: list[Mapping],
) -> tuple[int, str] | None:
    try:
        head = memory.read(address, 24)
    except OSError:
        return None
    while head and head[0] == 0x90:
        address += 1
        try:
            head = memory.read(address, 24)
        except OSError:
            return None
    if len(head) < 23:
        return None
    if head.startswith(NATIVE_REPORT_SIGNATURE):
        return address, "native prologue"
    if head[0] == 0xE9:
        target = address + 5 + struct.unpack_from("<i", head, 1)[0]
        descriptor = (
            head[5:7] == b"\x48\xb8"
            and head[15:19] == b"\x49\x89\x84\x24"
            and head[20:23] == b"\x01\x00\x00"
        )
        if address_in_mappings(target, executable) and descriptor:
            return address, f"VM bridge to {target:#x}"
    return None


def find_report_helper_fallback(
    memory: ProcessMemory,
    executable: list[Mapping],
    max_lookback: int = 0x300,
) -> int:
    candidates: list[int] = []
    for mapping in executable:
        data = memory.read(mapping.begin, mapping.end - mapping.begin)
        start = 0
        while True:
            prefix = data.find(REPORT_HELPER_EPILOGUE_PREFIX, start)
            if prefix < 0:
                break
            suffix = prefix + len(REPORT_HELPER_EPILOGUE_PREFIX) + 4
            if data[suffix : suffix + len(REPORT_HELPER_EPILOGUE_SUFFIX)] == REPORT_HELPER_EPILOGUE_SUFFIX:
                epilogue_end = suffix + len(REPORT_HELPER_EPILOGUE_SUFFIX)
                entry_addr = mapping.begin + epilogue_end
                if _valid_violation_entry_at(memory, entry_addr, executable) is not None:
                    window_start = max(0, prefix - max_lookback)
                    window = data[window_start:prefix]
                    found_starts = []
                    for rel in range(len(window) - 4):
                        if rel > 0 and window[rel - 1] not in (0xC3, 0x90, 0xCC, 0x00):
                            continue
                        chunk = window[rel:]
                        if any(chunk.startswith(p) for p in PROLOGUE_STARTS):
                            found_starts.append(mapping.begin + window_start + rel)
                    if len(found_starts) == 1:
                        candidates.append(found_starts[0])
            start = prefix + 1

    if len(candidates) != 1:
        addrs = ", ".join(f"{addr:#x}" for addr in candidates) or "none"
        raise DetectionError(
            f"report helper fallback is not unique ({len(candidates)} matches: {addrs})"
        )
    return candidates[0]

def parse_maps(text: str) -> list[Mapping]:
    mappings = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue
        begin, end = (int(value, 16) for value in fields[0].split("-"))
        mappings.append(
            Mapping(
                begin=begin,
                end=end,
                permissions=fields[1],
                offset=int(fields[2], 16),
                path=fields[5] if len(fields) == 6 else "",
            )
        )
    return mappings


def find_eac_mappings(mappings: list[Mapping]) -> list[Mapping]:
    candidates = [
        mapping
        for mapping in mappings
        if mapping.offset == 0
        and mapping.end - mapping.begin >= 0x10000
        and "/memfd:" in mapping.path
    ]
    if len(candidates) != 1:
        raise DetectionError(
            f"expected one EAC memfd base mapping, found {len(candidates)}"
        )

    base_mapping = candidates[0]
    module = [
        mapping
        for mapping in mappings
        if mapping.path == base_mapping.path
        and base_mapping.begin <= mapping.begin < base_mapping.begin + MAX_MODULE_SIZE
    ]
    if not module:
        raise DetectionError("EAC mappings disappeared")
    return sorted(module, key=lambda mapping: mapping.offset)


def executable_mappings(module: list[Mapping]) -> list[Mapping]:
    executable = [mapping for mapping in module if "x" in mapping.permissions]
    if not executable:
        raise DetectionError("EAC has no executable mapping")
    return executable


def find_all(data: bytes, pattern: bytes) -> list[int]:
    matches = []
    start = 0
    while True:
        found = data.find(pattern, start)
        if found < 0:
            return matches
        matches.append(found)
        start = found + 1


def find_unique_pattern(
    memory: ProcessMemory,
    mappings: list[Mapping],
    pattern: bytes,
    label: str,
) -> int:
    matches = []
    for mapping in mappings:
        data = memory.read(mapping.begin, mapping.end - mapping.begin)
        matches.extend(mapping.begin + offset for offset in find_all(data, pattern))
    if len(matches) != 1:
        offsets = ", ".join(f"{address:#x}" for address in matches) or "none"
        raise DetectionError(
            f"{label} signature is not unique ({len(matches)} matches: {offsets})"
        )
    return matches[0]


def address_in_mappings(address: int, mappings: list[Mapping]) -> bool:
    return any(mapping.begin <= address < mapping.end for mapping in mappings)


def report_entry_after_helper(
    memory: ProcessMemory,
    helper: int,
    executable: list[Mapping],
) -> tuple[int, str]:
    containing = next(
        (mapping for mapping in executable if mapping.begin <= helper < mapping.end),
        None,
    )
    if containing is None:
        raise DetectionError("report helper is outside executable mappings")

    size = min(0x300, containing.end - helper)
    body = memory.read(helper, size)
    matches = []
    start = 0
    while True:
        prefix = body.find(REPORT_HELPER_EPILOGUE_PREFIX, start)
        if prefix < 0:
            break
        suffix = prefix + len(REPORT_HELPER_EPILOGUE_PREFIX) + 4
        if body[suffix:suffix + len(REPORT_HELPER_EPILOGUE_SUFFIX)] == REPORT_HELPER_EPILOGUE_SUFFIX:
            matches.append(suffix + len(REPORT_HELPER_EPILOGUE_SUFFIX))
        start = prefix + 1

    if len(matches) != 1:
        raise DetectionError(
            f"expected one report-helper epilogue, found {len(matches)}"
        )

    entry = helper + matches[0]
    head = memory.read(entry, 24)
    if head[0] == 0x90:
        entry += 1
        head = memory.read(entry, 24)
    if head.startswith(NATIVE_REPORT_SIGNATURE):
        return entry, "native prologue"

    if head[0] == 0xE9:
        target = entry + 5 + struct.unpack_from("<i", head, 1)[0]
        descriptor = (
            head[5:7] == b"\x48\xb8"
            and head[15:19] == b"\x49\x89\x84\x24"
            and head[20:23] == b"\x01\x00\x00"
        )
        if address_in_mappings(target, executable) and descriptor:
            return entry, f"VM bridge to {target:#x}"

    raise DetectionError(
        f"unsupported violation-entry shape at {entry:#x}: {head.hex()}"
    )


def find_code_cave(
    memory: ProcessMemory,
    executable: list[Mapping],
    size: int,
) -> int:
    for mapping in executable:
        data = memory.read(mapping.begin, mapping.end - mapping.begin)
        run_start = None
        for index in range(len(data) + 1):
            is_padding = index < len(data) and data[index] in (0x00, 0x90, 0xCC)
            if is_padding:
                if run_start is None:
                    run_start = index
            else:
                if run_start is not None and index - run_start >= size:
                    return mapping.begin + run_start
                run_start = None
    raise DetectionError(f"no executable code cave of at least {size} bytes")


def build_guard_stub(
    eac_base: int,
    wrapper: int,
    cave: int,
    original_head: bytes,
) -> bytes:
    # Fail only the observed erase shape: one page below EAC, with PROT_RWX.
    # All other calls execute the original wrapper unchanged.
    stub = bytearray()
    stub += bytes.fromhex("f30f1efa")
    stub += bytes.fromhex("4881fe00100000")
    size_jump = len(stub)
    stub += bytes.fromhex("0f8500000000")
    stub += bytes.fromhex("83fa07")
    protection_jump = len(stub)
    stub += bytes.fromhex("0f8500000000")
    stub += b"\x48\xb8" + struct.pack("<Q", eac_base)
    stub += bytes.fromhex("4839c7")
    range_jump = len(stub)
    stub += bytes.fromhex("0f8300000000")
    stub += PATCH_RETURN_ZERO

    original = len(stub)
    stub += original_head
    jump_back = len(stub)
    stub += b"\xe9\x00\x00\x00\x00"

    for jump in (size_jump, protection_jump, range_jump):
        struct.pack_into("<i", stub, jump + 2, original - (jump + 6))
    struct.pack_into(
        "<i",
        stub,
        jump_back + 1,
        wrapper + WRAPPER_HEAD_SIZE - (cave + jump_back + 5),
    )
    return bytes(stub)


def module_sha256(memory: ProcessMemory, module: list[Mapping]) -> str:
    digest = hashlib.sha256()
    position = 0
    for mapping in module:
        if mapping.offset > position:
            digest.update(b"\0" * (mapping.offset - position))
        data = memory.read(mapping.begin, mapping.end - mapping.begin)
        digest.update(data)
        position = mapping.offset + len(data)
    return digest.hexdigest()


def find_game_pid(exe: Path, prefix: Path) -> int | None:
    wanted_exe = ("Z:" + str(exe).replace("/", "\\")).lower().encode()
    wanted_prefix = str(prefix).rstrip("/")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            if not argv or argv[0].lower() != wanted_exe:
                continue
            environment = dict(
                item.split(b"=", 1)
                for item in (entry / "environ").read_bytes().split(b"\0")
                if b"=" in item
            )
            if environment.get(b"WINEPREFIX", b"").decode().rstrip("/") == wanted_prefix:
                return int(entry.name)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return None


def dll_mapping(mappings: list[Mapping], dll: Path) -> int | None:
    wanted = str(dll).lower().replace("\\", "/")
    for mapping in mappings:
        path = mapping.path.lower().replace("\\", "/")
        if mapping.offset == 0 and path == wanted:
            return mapping.begin
    return None


def become_subreaper() -> None:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER)")


def existing_path(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"path does not exist: {path}")
    return path


def install_patches(pid: int) -> tuple[int, int, str]:
    maps_text = Path(f"/proc/{pid}/maps").read_text()
    module = find_eac_mappings(parse_maps(maps_text))
    executable = executable_mappings(module)
    base = next(mapping.begin for mapping in module if mapping.offset == 0)

    #for m in module:
    #    print(f"{m.begin:#x}-{m.end:#x} {m.permissions} off={m.offset:#x} {m.path}", flush=True)
    #mem_tmp = ProcessMemory(pid)
    #with open("/tmp/eac_exec.bin", "wb") as f:
    #    for m in executable:
    #        f.write(mem_tmp.read(m.begin, m.end - m.begin))
    #mem_tmp.close()
    #print("dumped /tmp/eac_exec.bin", flush=True)
    memory = ProcessMemory(pid)
    try:
        wrapper = find_unique_pattern(
            memory, executable, MPROTECT_SIGNATURE, "mprotect wrapper"
        )
        try:
            helper = find_unique_pattern(
                memory, executable, REPORT_HELPER_SIGNATURE, "report helper"
            )
        except DetectionError as exc:
            if "(0 matches: none)" not in str(exc):
                raise
            helper = find_report_helper_fallback(memory, executable)
            print(f"report helper (fallback): {helper:#x}", flush=True)
        
        report_entry, report_shape = report_entry_after_helper(
            memory, helper, executable
        )
        fingerprint = module_sha256(memory, module)

        original_wrapper = memory.read(wrapper, WRAPPER_HEAD_SIZE)
        if not original_wrapper.startswith(MPROTECT_SIGNATURE[:WRAPPER_HEAD_SIZE]):
            raise DetectionError("mprotect wrapper changed during detection")

        cave = find_code_cave(memory, executable, MIN_CODE_CAVE_SIZE)
        stub = build_guard_stub(base, wrapper, cave, original_wrapper)
        if len(stub) > MIN_CODE_CAVE_SIZE:
            raise DetectionError("guard stub no longer fits the selected code cave")

        print(f"EAC base: {base:#x}", flush=True)
        print(f"EAC mapped-image SHA-256: {fingerprint}", flush=True)
        print(f"mprotect wrapper: EAC+{wrapper - base:#x}", flush=True)
        print(f"report helper: EAC+{helper - base:#x}", flush=True)
        print(
            f"violation entry: EAC+{report_entry - base:#x} ({report_shape})",
            flush=True,
        )
        print(f"code cave: EAC+{cave - base:#x}", flush=True)

        wrapper_patch = bytearray(
            b"\xe9" + struct.pack("<i", cave - (wrapper + 5))
        )
        wrapper_patch += b"\x90" * (WRAPPER_HEAD_SIZE - len(wrapper_patch))

        writes = [
            (cave, stub, "guard stub"),
            (wrapper, bytes(wrapper_patch), "mprotect wrapper"),
            (report_entry, PATCH_RETURN_ZERO, "violation entry"),
        ]
        originals = [
            (address, memory.read(address, len(patch)))
            for address, patch, _ in writes
        ]
        applied = 0
        try:
            for address, patch, label in writes:
                applied += 1
                memory.write(address, patch)
                if memory.read(address, len(patch)) != patch:
                    raise OSError(f"{label} patch verification failed")
        except OSError:
            for address, original in reversed(originals[:applied]):
                memory.write(address, original)
            raise

        print("patches installed and verified", flush=True)
        return base, report_entry, fingerprint
    finally:
        memory.close()


def wait_for_eac(pid: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            raise RuntimeError("game exited before EAC loaded")
        try:
            mappings = parse_maps(Path(f"/proc/{pid}/maps").read_text())
            module = find_eac_mappings(mappings)
            executable_mappings(module)
            return
        except (DetectionError, FileNotFoundError, ProcessLookupError) as error:
            last_error = error
        time.sleep(0.002)
    raise RuntimeError(f"EAC module did not load: {last_error}")


def watch_dll_header(pid: int, dll: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    seen = False
    memory = ProcessMemory(pid)
    try:
        while time.monotonic() < deadline:
            if not Path(f"/proc/{pid}").exists():
                print("game process ended while checking the DLL", file=sys.stderr)
                return False
            mappings = parse_maps(Path(f"/proc/{pid}/maps").read_text())
            base = dll_mapping(mappings, dll)
            if base is not None:
                seen = True
                header = memory.read(base, 2)
                if header != b"MZ":
                    print(f"DLL header changed to {header!r}", file=sys.stderr)
                    return False
            time.sleep(0.1)
    finally:
        memory.close()

    if not seen:
        print(f"DLL mapping was not observed: {dll}", file=sys.stderr)
        return False
    print(f"DLL header remained b'MZ' for {timeout:g}s", flush=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=existing_path, help="game executable path")
    parser.add_argument("--dll", required=True, type=existing_path, help="game-local DLL path")
    parser.add_argument("--launcher", required=True, type=existing_path, help="Wine/Proton executable path")
    parser.add_argument("--compat", required=True, type=existing_path, help="STEAM_COMPAT_DATA_PATH")
    parser.add_argument("--steam-client", required=True, type=existing_path, help="STEAM_COMPAT_CLIENT_INSTALL_PATH")
    parser.add_argument("--overrides", help="WINEDLLOVERRIDES (default: <DLL name>=n,b)")
    parser.add_argument("--wait", type=float, default=90.0, help="seconds to wait for the game and EAC")
    parser.add_argument("--wait-after", type=float, default=30.0, help="seconds to verify that the DLL header survives")
    args = parser.parse_args()

    if not args.exe.is_file() or not args.dll.is_file() or not args.launcher.is_file():
        parser.error("--exe, --dll, and --launcher must be files")
    if not args.compat.is_dir() or not args.steam_client.is_dir():
        parser.error("--compat and --steam-client must be directories")
    if args.dll.parent != args.exe.parent:
        parser.error("--dll must be in the same directory as --exe")

    prefix = args.compat / "pfx"
    launch_exe = args.exe.with_name("launch.exe")
    if not prefix.is_dir():
        parser.error(f"Wine prefix does not exist: {prefix}")
    if not launch_exe.is_file():
        parser.error(f"EAC launcher does not exist: {launch_exe}")

    become_subreaper()
    environment = os.environ.copy()
    environment["STEAM_COMPAT_DATA_PATH"] = str(args.compat)
    environment["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = str(args.steam_client)
    environment["WINEDLLOVERRIDES"] = args.overrides or f"{args.dll.name}=n,b"
    environment["PROTON_LOG"] = "0"

    process = subprocess.Popen(
        [str(args.launcher), "run", str(launch_exe)],
        env=environment,
        cwd=str(args.exe.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"launcher started (pid {process.pid})", flush=True)

    deadline = time.monotonic() + args.wait
    pid = None
    while time.monotonic() < deadline:
        pid = find_game_pid(args.exe, prefix)
        if pid is not None:
            break
        time.sleep(0.01)
    if pid is None:
        print("game process not found", file=sys.stderr)
        return 1

    print(f"game pid: {pid}", flush=True)
    try:
        wait_for_eac(pid, max(0.0, deadline - time.monotonic()))
        install_patches(pid)
        if args.wait_after > 0 and not watch_dll_header(pid, args.dll, args.wait_after):
            return 1
    except (DetectionError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
