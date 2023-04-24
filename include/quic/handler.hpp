#pragma once

#include "utils.hpp"
#include "client.hpp"
#include "crypto.hpp"

#include <unordered_map>
#include <uvw.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
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
	//class Client;
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

    //template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool> = true>
	struct ClientManager
	{
		// Client endpoint linked to this tunnel instance
		std::unique_ptr<Client> client;
		open_callback open_cb;
		close_callback close_cb;

		std::string remote_host, local_host;
		uint16_t remote_port, local_port;
		Address remote_addr, local_addr;

		// UDP handles
        std::unordered_set<std::shared_ptr<uvw::UDPHandle>> udp_handles;
		std::shared_ptr<uvw::UDPHandle> udp_handle;

        // Cert information for each connection is stored in a map indexed by ConnectionID.
        // As a result, each connection (also mapped in client->conns) can have its own
        // TLS cert info. Each connection also stores within it the gnutls_session_t and
        // gnutls_certificate_credentials_t objects used to initialize its ngtcp2 things
        std::unordered_map<ConnectionID, TLSCertManager> cert_managers;

        inline void
        set_addrs(std::string laddr, uint16_t lport, std::string raddr, uint16_t rport)
        {
            local_host = laddr;
            local_port = lport;
            remote_host = raddr;
            remote_port = rport;
            local_addr = Address{local_host, local_port};
            remote_addr = Address{remote_host, remote_port};
        }

		~ClientManager();
	};

	class Handler 
	{
		friend class Context;
		
		public:
			explicit Handler(std::shared_ptr<uvw::Loop> loop_ptr = nullptr);
			~Handler();

			std::shared_ptr<uvw::AsyncHandle> io_trigger;
            std::shared_ptr<uvw::Loop> ev_loop;

			std::shared_ptr<uvw::Loop>
    		loop();

			void
			receive_packet(Address remote, const bstring& buf);

			//  Sends packet to 'destination' containing 'data'
            void
            send_datagram(uvw::UDPHandle handle, std::string host, uint8_t port, char* data, size_t datalen);
            void
            send_datagram(uvw::UDPHandle handle, std::string host, uint8_t port, std::string data);

			void
			close(bool all=false);

			void
			listen(std::string host, uint16_t port);

            template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool> = true>
            int
            udp_connect_secured(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
                T cert, open_callback on_open, close_callback on_close);

			int
			udp_connect_unsecured(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
                open_callback on_open, close_callback on_close);

			ConnectionID 
			make_client(std::shared_ptr<ClientManager> client_manager);

			void 
			make_server(std::string host, uint16_t port);

            /****** TEST FUNCTIONS ******/
            void
            echo_server_test(std::string host, uint16_t port);
			int
			connect_oneshot_test(
                std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, std::string message="");
            // TOFIX: add cert verification to nullcert tests
            void
            echo_server_nullcert_test(std::string host, uint16_t port, TLSCert cert);
            int
			connect_oneshot_nullcert_test(
                std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, TLSCert cert, std::string message="");
            /****************************/

        private:
			//	Maps outbound connections that are currently being managed by handler object
			//		- key: std::string{remote_address}
			//		- value: pointer to client manager object
			//
			//	For example, when a user opens a connection to 127.0.0.1:5440, the ClientManager ptr
			//	will be indexed to "127.0.0.1:5440"
			std::map<std::string, std::unique_ptr<ClientManager>> client_tunnels;

			std::unique_ptr<Server> server_ptr;

			//	Tead callback is passed to ev_io_init, then the corresponding connection
			//	is stored in ev_io.data
			read_callback read_cb;
			//	Timer callback is passed to ev_timer_init, then the corresponding connection
			//	is stored in ev_timer.data
			timer_callback timer_cb;
			
			server_callback<Address> server_cb;

			///	keep ev loop open for cleanup
			std::shared_ptr<int> keep_alive = std::make_shared<int>(0); 

	};
}	// namespace oxen::quic
