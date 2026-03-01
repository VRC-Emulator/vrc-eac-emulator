#pragma once

#include <common/protocol/packet.h>

#include <future>

class websocket_server {
	static void run_server(int port);

public:
	static void launch(int port);

	static void send_packet(const std::shared_ptr<packet>& packet);

	static bool has_connection();

	static void wait_for_connection();

	static void tick();

private:
	static void performSend();

	static void performReceive();
};
