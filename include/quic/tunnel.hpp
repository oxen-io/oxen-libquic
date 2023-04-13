#pragma once

#include "utils.hpp"

#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <map>
#include <queue>
#include <unordered_set>
#include <netinet/ip.h>

#include <uvw/async.h>
#include <uvw/timer.h>
#include <uvw/poll.h>
#include <uvw/tcp.h>
#include <uvw/loop.h>
#include <uvw/emitter.h>

#define IP_TUNNEL_MAX_BUFFER_SIZE 4096

namespace oxen::quic
{
	class Client;
	class Server;

	//	Callbacks for opening quic connections and closing tunnels
    using open_callback = std::function<void(bool success, void* user_data)>;
    using close_callback = std::function<void(int rv, void* user_data)>;
	//	Callbacks for ev timer functionality
	using read_callback = std::function<void(uvw::Loop* loop, uvw::TimerEvent* ev, int revents)>;
	using timer_callback = std::function<void(int nwrite, void* user_data)>;

	struct ClientTunnel
	{
		// client endpoint linked to this tunnel instance
		std::unique_ptr<Client> client;
		open_callback open_cb;
		close_callback close_cb;
		// TCP listening socket
		std::shared_ptr<uvw::TCPHandle> tcp_socket;
		// Accepted TCP connections
		std::unordered_set<std::shared_ptr<uvw::TCPHandle>> conns;
		// Queue of incoming connections waiting for available stream
		std::queue<std::weak_ptr<uvw::TCPHandle>> pending;

		~ClientTunnel();
	};

	class Tunnel 
	{
		public:
			int tun_fd;
			struct sockaddr remote_addr;
			unsigned char *read_buffer;

			std::shared_ptr<uvw::Loop>
    		get_loop();

			void
    		flush_pending_incoming(ClientTunnel& ct);

			void
			receive_packet(Address remote, const bstring& buf);

			void
			close(uint16_t cid);

			std::pair<Address, uint16_t>
			open(
				std::string remote_address, uint16_t port, open_callback on_open, close_callback on_close, Address bind_addr);

			int 
			make_client(
				const uint16_t port, Address& remote, std::pair<const uint16_t, ClientTunnel>& row);
			int 
			make_server();

			std::shared_ptr<uvw::AsyncHandle> io_trigger;
            
            std::shared_ptr<uvw::Loop> ev_loop;

		private:	
			std::map<uint16_t, ClientTunnel> client_tunnels;

			std::unique_ptr<Server> server_ptr;

			//	read callback is passed to ev_io_init, then
			//		the corresponding connection is stored in ev_io.data
			//	timer callback is passed to ev_timer_init, then
			//		the corresponding connection is stored in ev_timer.data
			read_callback read_cb;
			timer_callback timer_cb;

	};

	int ip_tunnel_init(Tunnel* tunnel);
	int ip_tunnel_open(Tunnel* tunnel, const char* dev);
	int ip_tunnel_close(Tunnel* tunnel);
	ssize_t ip_tunnel_read(Tunnel* tunnel, unsigned char* buffer,
						size_t buffer_size);
	ssize_t ip_tunnel_write(Tunnel* tunnel, const unsigned char* buffer,
							size_t buffer_size);
}	// namespace oxen::quic
