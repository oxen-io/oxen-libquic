#pragma once

#include "utils.hpp"

#include <uvw/emitter.h>
#include <uvw/stream.h>
#include <uvw/tcp.h>
#include <uvw/async.h>
#include <uvw/timer.h>

#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <map>
#include <queue>
#include <unordered_set>
#include <netinet/ip.h>


#define IP_TUNNEL_MAX_BUFFER_SIZE 4096

namespace oxen::quic
{
	class Client;
	class Stream;
	class Server;
	class Context;
	class Connection;

	//	Callbacks for opening quic connections and closing tunnels
    using open_callback = std::function<void(bool success, void* user_data)>;
    using close_callback = std::function<void(int rv, void* user_data)>;
	//	Callbacks for ev timer functionality
	using read_callback = std::function<void(uvw::Loop* loop, uvw::TimerEvent* ev, int revents)>;
	using timer_callback = std::function<void(int nwrite, void* user_data)>;
	//	Callback for server connectivity
	template <typename T>
	using server_callback = std::function<T(uint16_t port)>;

	struct ClientTunnel
	{
		// Client endpoint linked to this tunnel instance
		std::unique_ptr<Client> client;
		open_callback open_cb;
		close_callback close_cb;
		// TCP listening socket
		std::shared_ptr<uvw::TCPHandle> tcp_socket;
		// Accepted TCP connections
		std::unordered_set<std::shared_ptr<uvw::TCPHandle>> conns;

		~ClientTunnel();
	};

	class Tunnel 
	{
		friend class Context;
		
		public:
			explicit Tunnel(Context& ctx);
			~Tunnel();

			int tun_fd;
			struct sockaddr remote_addr;
			unsigned char *read_buffer;

			std::shared_ptr<uvw::AsyncHandle> io_trigger;
            std::shared_ptr<uvw::Loop> ev_loop;

			std::shared_ptr<uvw::Loop>
    		loop();

			void
			receive_packet(Address remote, const bstring& buf);

			//  Sends packet to 'destination' containing 'data'. io_result is implicitly
            //  convertible to bool if successful, or error code if not
			//	
			//	"type" refers to the value set in the first bit:
			//		CLIENT_TO_SERVER=1
			//		SERVER_TO_CLIENT=2
            io_result
            send_packet(const Address& destination, bstring data, uint8_t ecn, std::byte type);

			void
			close();

			void
			listen(uint16_t port);

			void
			flush_incoming(ClientTunnel& ct);

			int
			open(
				std::string remote_address, uint16_t remote_port, open_callback on_open, close_callback on_close, Address& bind_addr);

			void 
			make_client(
				const uint16_t remote_port, Address& remote);
			
			void 
			make_server();

		private:
			std::unique_ptr<ClientTunnel> client_tunnel;
			std::unique_ptr<Server> server_ptr;
			//std::unique_ptr<Context> ctx_ptr;

			//	read callback is passed to ev_io_init, then
			//		the corresponding connection is stored in ev_io.data
			//	timer callback is passed to ev_timer_init, then
			//		the corresponding connection is stored in ev_timer.data
			read_callback read_cb;
			timer_callback timer_cb;
			
			server_callback<Address> server_cb;

			//	keep ev loop open for cleanup
			std::shared_ptr<int> keep_alive = std::make_shared<int>(0); 
	};
}	// namespace oxen::quic
