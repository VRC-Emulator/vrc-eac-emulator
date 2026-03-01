#include "begin_session_handler.h"

#include "common/protocol/packets/begin_session_packet.h"

#include "../../eos/eos_anticheat.h"
#include "../../eos/eos_platform.h"

void begin_session_handler::handle(std::shared_ptr<packet> packet) {
	auto begin_session = std::static_pointer_cast<begin_session_packet>(packet);

	auto anticheat_interface = eos_platform::get_anticheat_client_interface();
	if (anticheat_interface == NULL) {
		PLOGF.printf("Could not retrieve anticheat client interface");
		return;
	}

	EOS_AntiCheatClient_BeginSessionOptions options{};
	options.ApiVersion = begin_session->api_version;
	options.LocalUserId = begin_session->user_id;
	options.Mode = begin_session->mode;

	auto begin_result = eos_anticheat::begin_session(anticheat_interface, options);
	if (begin_result == EOS_Success) {
		PLOGI.printf("AntiCheat session successfully began");
		return;
	}

	PLOGW.printf("BeginSession failed (%d). Trying EndSession -> BeginSession recovery", begin_result);
	EOS_AntiCheatClient_EndSessionOptions end_options{};
	end_options.ApiVersion = options.ApiVersion;
	auto end_result = eos_anticheat::end_session(anticheat_interface, end_options);
	if (end_result != EOS_Success) {
		PLOGW.printf("Recovery EndSession returned %d", end_result);
	}

	begin_result = eos_anticheat::begin_session(anticheat_interface, options);
	if (begin_result == EOS_Success) {
		PLOGI.printf("AntiCheat session successfully recreated");
	} else {
		PLOGE.printf("Failed to begin AntiCheat session after recovery (begin=%d, end=%d)", begin_result, end_result);
	}
}
