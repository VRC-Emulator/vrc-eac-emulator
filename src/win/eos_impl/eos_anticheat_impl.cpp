#include "../emulator_client.h"
#include "eos_anticheat_impl.h"
#include "base64.hpp"
#include "common/eos/eos_anticheat_types.h"
#include "common/eos/eos_api.h"
#include "common/protocol/packets/begin_session_packet.h"
#include "common/protocol/packets/end_session_packet.h"
#include "common/protocol/packets/receive_message_packet.h"

#include <mutex>

namespace {
	std::mutex session_state_mutex;
	bool has_active_session = false;
	int32_t last_begin_api_version = 0;
	EOS_ProductUserId last_begin_user_id = 0;
	EOS_EAntiCheatClientMode last_begin_mode = 0;
}

EOS_DECLARE_FUNC(EOS_EResult)
DummyEOS_AntiCheatClient_BeginSession(EOS_HAntiCheatClient handle, const EOS_AntiCheatClient_BeginSessionOptions* options) {
	PLOGI.printf("Beginning session with mode: %d", options->Mode);
	auto packet = std::make_shared<begin_session_packet>();
	packet->api_version = options->ApiVersion;
	packet->user_id = options->LocalUserId;
	packet->mode = options->Mode;
	emulator_client::get_instance()->send_packet(packet);
	{
		std::lock_guard lock(session_state_mutex);
		has_active_session = true;
		last_begin_api_version = options->ApiVersion;
		last_begin_user_id = options->LocalUserId;
		last_begin_mode = options->Mode;
	}

	return EOS_Success;
}

EOS_DECLARE_FUNC(EOS_EResult)
DummyEOS_AntiCheatClient_EndSession(EOS_HAntiCheatClient handle, const EOS_AntiCheatClient_EndSessionOptions* options) {
	PLOGI.printf("Ending session");
	auto packet = std::make_shared<end_session_packet>();
	packet->options.ApiVersion = options->ApiVersion;
	emulator_client::get_instance()->send_packet(packet);
	{
		std::lock_guard lock(session_state_mutex);
		has_active_session = false;
	}

	return EOS_Success;
}

EOS_DECLARE_FUNC(EOS_EResult)
DummyEOS_AntiCheatClient_ReceiveMessageFromServer(EOS_HAntiCheatClient handle, const EOS_AntiCheatClient_ReceiveMessageFromServerOptions* options) {
	std::vector<char> message_bytes;
	for (int i = 0; i < options->DataLengthBytes; i++) {
		message_bytes.push_back(static_cast<const char*>(options->Data)[i]);
	}
	auto message_base64 = base64::encode_into<std::string>(message_bytes.begin(), message_bytes.end());

	auto packet = std::make_shared<receive_message_packet>();
	packet->api_version = options->ApiVersion;
	packet->base64_message = nullable_string(message_base64);
	packet->data_length_bytes = options->DataLengthBytes;
	emulator_client::get_instance()->send_packet(packet);

	return EOS_Success;
}

void recreate_anticheat_session_if_needed() {
	int32_t api_version;
	EOS_ProductUserId user_id;
	EOS_EAntiCheatClientMode mode;
	{
		std::lock_guard lock(session_state_mutex);
		if (!has_active_session) {
			return;
		}
		api_version = last_begin_api_version;
		user_id = last_begin_user_id;
		mode = last_begin_mode;
	}

	if (emulator_client::get_instance() == nullptr) {
		return;
	}

	PLOGW.printf("Connection was re-established. Recreating AntiCheat session...");
	auto end_packet = std::make_shared<end_session_packet>();
	end_packet->options.ApiVersion = api_version;
	emulator_client::get_instance()->send_packet(end_packet);

	auto begin_packet = std::make_shared<begin_session_packet>();
	begin_packet->api_version = api_version;
	begin_packet->user_id = user_id;
	begin_packet->mode = mode;
	emulator_client::get_instance()->send_packet(begin_packet);
}
