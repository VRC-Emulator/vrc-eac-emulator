#include "websocket_server.h"

#include <common/constants.h>
#include <common/protocol/packet_codec.h>
#include <hv/WebSocketServer.h>
#include <plog/Log.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "../handlers/handler_registry.h"
#include "hv/WebSocketChannel.h"

std::shared_ptr<hv::WebSocketServer> server;
std::vector<WebSocketChannelPtr> channels;
std::mutex channels_mutex, send_mutex, receive_mutex;
std::condition_variable connection_cv;
std::mutex connection_mutex;
std::atomic<bool> has_active_connection = false;
std::vector<std::shared_ptr<packet> > send_queued_packets, receive_queued_packets;

void websocket_server::run_server(int port) {
	hv::WebSocketService service;
	service.onopen = [&](const WebSocketChannelPtr& channel, const HttpRequestPtr& req) {
		PLOGD.printf("A connection established");
		{
			std::lock_guard lock(channels_mutex);
			channels.push_back(channel);
		}

		has_active_connection = true;
		connection_cv.notify_all();
	};
	service.onclose = [&](const WebSocketChannelPtr& channel) {
		std::lock_guard channels_lock(channels_mutex);
		channels.erase(std::remove_if(channels.begin(), channels.end(), [&](const WebSocketChannelPtr& current) {
			return current == channel;
		}), channels.end());
		if (!channels.empty()) {
			return;
		}

		has_active_connection = false;
		{
			std::lock_guard send_lock(send_mutex);
			send_queued_packets.clear();
		}
		{
			std::lock_guard receive_lock(receive_mutex);
			receive_queued_packets.clear();
		}
		PLOGW.printf("Connection closed. Waiting for the next client...");
	};
	service.onmessage = [](const WebSocketChannelPtr& channel, const std::string& msg) {
		std::lock_guard lock(receive_mutex);
		read_stream stream(msg.data(), msg.size());
		auto packet = packet_codec::decode(stream);
		if (packet) {
			receive_queued_packets.push_back(packet);
		} else {
			PLOGF.printf("Invalid packet retrieved");
		}
		stream.close();
	};

	server = std::make_shared<hv::WebSocketServer>(&service);
	server->setHost();
	server->setPort(port);
	server->setThreadNum(4);
	server->run();
}

void websocket_server::launch(int port) {
	PLOGI.printf("Starting server on %d", port);
	std::thread([port]() {
		run_server(port);
	}).detach();

	PLOGI.printf("Waiting for a connection...");
	wait_for_connection();
}

void websocket_server::send_packet(const std::shared_ptr<packet>& packet) {
	std::lock_guard lock(send_mutex);
	send_queued_packets.push_back(packet);
}

bool websocket_server::has_connection() {
	return has_active_connection.load();
}

void websocket_server::wait_for_connection() {
	if (has_connection()) {
		return;
	}

	std::unique_lock lock(connection_mutex);
	connection_cv.wait(lock, []() {
		return has_active_connection.load();
	});
}

void websocket_server::tick() {
	performReceive();
	performSend();
}

void websocket_server::performSend() {
	std::vector<WebSocketChannelPtr> channels_snapshot;
	{
		std::lock_guard channels_lock(channels_mutex);
		channels_snapshot = channels;
	}

	std::lock_guard send_lock(send_mutex);
	for (auto& packet : send_queued_packets) {
		write_stream stream = packet_codec::encode(packet);
		auto buf = stream.as_buffer();
		for (auto channel : channels_snapshot) {
			channel->send(static_cast<char*>(buf.data), buf.size, WS_OPCODE_BINARY);
		}
		buf.free();
	}
	send_queued_packets.clear();
}

void websocket_server::performReceive() {
	std::lock_guard lock(receive_mutex);
	for (const auto packet : receive_queued_packets) {
		if (const auto handler = handler_registry::get_handler_by_id(packet->get_id())) {
			handler(packet);
		}
	}
	receive_queued_packets.clear();
}
