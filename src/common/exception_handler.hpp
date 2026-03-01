#pragma once

#include <crashlog/address.hpp>
#include <crashlog/crashlog.hpp>
#include <crashlog/exception.hpp>
#include <winuser.h>

#include <cstdio>
#include <sstream>
#include <string>
#include <type_traits>
#include <variant>

class exception_handler {
	template <typename... Ts>
	static std::string format_variant(const std::variant<Ts...>& value) {
		if (value.valueless_by_exception()) {
			return "<valueless>";
		}

		return std::visit([](const auto& arg) -> std::string {
			using T = std::decay_t<decltype(arg)>;
			if constexpr (std::is_same_v<T, bool>) {
				return arg ? "true" : "false";
			} else if constexpr (std::is_pointer_v<T>) {
				std::ostringstream oss;
				oss << static_cast<const void*>(arg);
				return oss.str();
			} else if constexpr (requires(std::ostringstream& os, const T& value) { os << value; }) {
				std::ostringstream oss;
				oss << arg;
				return oss.str();
			} else {
				return "<unprintable>";
			}
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
