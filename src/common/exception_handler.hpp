#pragma once

#include <crashlog/address.hpp>
#include <crashlog/crashlog.hpp>
#include <crashlog/exception.hpp>
#include <winuser.h>

#include <cstdio>
#include <sstream>
#include <string>
#include <variant>

class exception_handler {
	static std::string format_variant(const std::variant<std::string, int64_t, uint64_t>& value) {
		return std::visit([](auto&& arg) -> std::string {
			std::ostringstream oss;
			oss << arg;
			return oss.str();
		}, value);
	}

	static LONG WINAPI TopLevelExceptionFilter(struct _EXCEPTION_POINTERS *ExceptionInfo) {
		crashlog::initialize();

		auto info = crashlog::parse(ExceptionInfo);
		auto metadata = info.exceptionMetadata;

		std::ostringstream stream;
		stream << "========= Exception Info ==========\n";
		stream << "Exception At: " << crashlog::addressToString(metadata.address) << "\n";
		stream << "Exception Code: " << std::hex << metadata.exceptionCode << std::dec << " (" << metadata.exceptionName << ")\n";
		for (const auto& [key, value] : metadata.additionalInfo) {
			stream << "  " << key << ": " << format_variant(value) << "\n";
		}

		stream << "========= Stack Trace ===========\n";
		for (const auto& frame : info.stacktrace) {
			stream << crashlog::addressToString(frame) << "\n";
		}

		stream << "=========== Registers ================\n";
		for (const auto& [reg_name, reg_value] : info.registers) {
			stream << reg_name << ": " << std::hex << reg_value << std::dec << "\n";
		}

		printf("%s\n", stream.str().c_str());
		MessageBoxA(nullptr, stream.str().c_str(), "Crashed!", MB_OK | MB_ICONERROR);

		return 0;
	}

public:
	static void init() {
		SetUnhandledExceptionFilter(&TopLevelExceptionFilter);
	}
};
