#pragma once

#include "utils.hpp"
#include "client.hpp"
#include "crypto.hpp"

#include <uvw.hpp>

#include <unordered_map>
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
	class Network;
	class Connection;
    class ClientContext;
    class ServerContext;

	class Handler 
	{
		friend class Network;
		
		public:
			explicit Handler(std::shared_ptr<uvw::Loop> loop_ptr);
			~Handler();

			std::shared_ptr<uvw::AsyncHandle> io_trigger;
            std::shared_ptr<uvw::Loop> ev_loop;

			std::shared_ptr<uvw::Loop>
    		loop();

			void
			receive_packet(Address remote, const bstring& buf);

			//  Sends packet to 'destination' containing 'data'
            void
            send_datagram(std::shared_ptr<uvw::UDPHandle> handle, Address& destination, char* data, size_t datalen);
            void
            send_datagram(std::shared_ptr<uvw::UDPHandle> handle, Address& destination, std::string data);

			void
			close(bool all=false);

			void
			listen(std::string host, uint16_t port);

            template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool> = true>
            int
            udp_connect(Address& local, Address& remote, T cert, open_callback on_open, close_callback on_close);

			int
			udp_connect(Address& local, Address& remote, open_callback on_open, close_callback on_close);

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
			//	Maps client connections that are currently being managed by handler object
			//		- key: Address{remote_addr}
			//		- value: pointer to client context object
			//
			//	For example, when a user opens a connection to 127.0.0.1:5440, the ClientContext ptr
			//	will be indexed to Address{"127.0.0.1", "5440"}
            std::unordered_map<Address, std::shared_ptr<ClientContext>> clients;
            //	Maps server connections that are currently being managed by handler object
			//		- key: Address{local_addr}
			//		- value: pointer to server context object
			//
			//	For example, when a user listens to 127.0.0.1:4433, the ClientManager ptr
			//	will be indexed to Address{"127.0.0.1", "5440"}
            std::unordered_map<Address, std::shared_ptr<ServerContext>> servers;

			///	keep ev loop open for cleanup
			std::shared_ptr<int> keep_alive = std::make_shared<int>(0); 

        public:

	};
}	// namespace oxen::quic



/*

We need to open the socket in quicinet object creation
    -> everything then shoves it into that one uvw::UDPHandle


How to add code blocks that do NOT run for things that do not satisfy the constexpr:
    template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool> = true>
    int udp_connect(Address& local, Address& remote, T cert, open_callback on_open, close_callback on_close) 
    {
        if constexpr (!std::is_same_v<T, NullCert>) 
        {
            // code ignored for NullCert 
        }
    }

Single constexpr function that can return either a std::array<std::string, N> or a std::string based on whether N > 1 or == 1:
https://github.com/jagerman/libsession-util-nodejs/blob/node-addon-api/src/utilities.hpp#L34

constexpr function that wraps a callback and does different things based on what the callback returns:
https://github.com/jagerman/libsession-util-nodejs/blob/node-addon-api/src/utilities.hpp#L158


Perfect Forwarding
https://en.cppreference.com/w/cpp/utility/forward
How to pass a number of cert arguments and fwd them along:
    template <typename CertType, typename... CertArgs>
    int udp_connect(Address& local, Address& remote, open_callback on_open, close_callback on_close, CertArgs&&... cert_args) 
    {
        // ...
        tls_manager.cert = std::make_unique<CertType>(std::forward<CertArgs>(cert_args)...);
    }


Can pass cert in, which will convert itself into context based on the type of cert:
    struct TLSCert 
    {
        virtual std::unique_ptr<TLSContext> into_context() && = 0;
    };
    struct GNUTLSCert : TLSCert 
    {
        std::unique_ptr<TLSContext> into_context() && override 
        {
            return std::make_unique<GNUTLSContext>(std::move(*this));
        }
    };

    struct TLSContext 
    { 
        // virtual methods, etc
    };
    struct GNUTLSContext 
    {
        GNUTLSCert cert;
        GNUTLSContext(GNUTLSCert&& cert) : cert{std::move(cert)} {}
    };

Then when you need to construct a context from a cert:
    auto context = std::move(cert).into_context(); 
    // context is unique_ptr<TLSContext>, but holds a GNUTLSContext


Sample usage flow
    - establish a QUIC connection to remote:port
        - this works with ngtcp2 calls (which in turn will fire into TLSContext callbacks) to do TLS/QUIC handshaking
        - ngtcp2 gives us the packets we need to send to remote:port
        - response packets get fed into ngtcp2, it might generate more packets, etc.
        - eventually connection gets established, verified, and handshaked.

    - create a new QUIC  stream from that connection

    - send some stream data with: stream.send("hello");
        - This adds "hello" to that stream's buffer
        - flush_streams (or equivalent) picks that up, feeds it into ngtcp2
        - ngtcp2 gives us a ready to go packet
        - we fire the packet via clearnet UDP at the remote:port

    //

Sample API Usage 1:

    Network net{};
    auto server1 = net.listen("127.0.0.1:5440"_local, &tls1);
    auto server2 = net.listen("127.0.0.1:4646"_local, &tls2);

    auto client1 = net.connect("127.0.0.1:4920"_remote, &tls3, &remote_cert2); // binds to anyaddr udp handle
    auto client2 = server1.connect("127.0.0.1:4433"_remote, &remote_cert1); // binds to 127.0.0.1:5440, uses tls1
    auto client3 = net.connect("127.0.0.1:7777"_remote, "127.0.0.1:7778"_local, &local_cert3, &remote_cert3);
    auto client4 = client1.connect("127.0.0.1:2222"_remote, &remote_cert1); // binds to client1's addr, uses client1's tls

    auto stream = client1.make_stream();


Sample API Usage 2:

    Network net{};
    // Full:
        auto ep = net.endpoint(&tls, //Bind addr=//"127.0.0.1:1111");
        auto server = ep.server_listen(// callbacks, extra junk );
        auto client1 = ep.client_connect(remote_addr1, &remote_tls1);
        auto client2 = ep.client_connect(remote_addr2, &remote_tls2, Network::local_tls{&tls2});

    // Simple:
        auto client3 = net.connect("1.1.1.1:5555", &mytls, &theirtls);
        // client3 is a convenience shortcut for:
        auto client4 = net.endpoint(&mytls).client_connect("1.1.1.1:5555", &theirtls);

        // Connects without client cert authentication:
        auto client5 = net.connect("1.1.1.1:5555", &theirtls);
        auto client6 = net.endpoint().client_connect("1.1.1.1:5555", &theirtls);


Sample API Usage 3:

    Network net{};
    auto ep1 = net.endpoint(&local_addr1, &tls1);
    auto ep2 = net.endpoint(&local_addr2, &tlswhatever);

    auto server = ep.make_server(...)

    auto client1 = ep.client_connect(&remote_addr1, &tls2, &remote_tls3);
    auto client2 = ep.client_connect(&remote_addr2, &tls3, &remote_tls4);

    auto client3 = net.connect(&remote_addr3, ...);
    auto client4 = net.connect(&remote_addr4, ...);


// Necessary certs and parameters:

server (listen only):
    - cert
    - private key
    - optional: callback for validating client cert, depending on use case
        - can use jason's template examples to pass other types of callbacks 

client:
    mode 1: i have the remote's cert
        method 1:
            - (O) client cert
            - (O) client private key
            - remote cert
        method 2:
            - remote cert

    mode 2: use the system CA (or some callback if no CA) to verify the remote's cert
        method 1:
            - (O) client cert
            - (O) client private key
            - server cert verification callback
        method 2:
            - server cert verification callback


Client: [server_cert, server_CA, system_CA, server_cert_callback] x [client_key/crt, no client key]

Server: [server_keycrt] x [client_callback, client_CA, no_client_verification] 



Can create tags around arguments, using templates to extract them to specify arguments however you want

    namespace opt {
        struct _base_addr 
        { 
            std::string addr; 
            _base_addr(std::string a) : addr{std::move(a)}; 
        };

        struct local_addr : _base_addr { using _base_addr::_base_addr; };

        struct remote_addr : _base_addr { using _base_addr::_base_addr; };

        struct _base_tls 
        { 
            int a, b, c; 
            _base_tls(int a, b, c) : a{a}, b{b}, c{c};
        };

        struct local_tls : _base_tls { using _base_tls::_base_tls; };
        
        struct remote_tls : _base_tls { using _base_tls::_base_tls; };

        struct timeout 
        {
            int seconds;
            timeout(int secs) : seconds{secs} {}; 
        };
    };

    using namespace quicinet::opt;

    net.connect(local_tls{1,2,3}, remote_addr{"1.2.3.4:5678"}, remote_tls{5,6,7}, local_addr{"10.0.0.1:4444"});

    template <typename... Opt>
    Client connect(Opt&&... opts)
    {
        Client c;
        handle_client_opt(c, std::forward<Opt>(opts)...);
    }

    void handle_client_opt(Client& c, opt::local_addr a) 
    {
        c.set_local_addr(std::move(a.addr)); 
    }

    void handle_client_opt(Client& c, opt::remote_addr a) 
    {
        c.set_remote_addr(std::move(a.addr)); 
    }


For doing this with Address:

    namespace opt 
    {
        // Method 1 (useful if there is more than just Address here)
        struct local_addr 
        {
            int x;
            Address a;
            template <typename... Args>
            local_addr(int x, Args&&... args) : a{std::forward<Args>(args)...}, x{x} {}
        };

        // Method 2:
        struct local_addr : Address { using Address::Address; };
    }

utils.hpp

namespace oxen::quic
{
    namespace opt
    {
        ...
    }
    ...

}

network.hpp

namespace oxen::quic
{
    using namespace opt
    ...
        other code
    ...

}

namespace opt 
{
    template <typename TLSType>
    struct local_tls : TLSType { using TLSType::TLSType; };
}


Wrapping callbacks for C API:
// *.c
typedef double (*) (double a, double b, void* context) some_callback_t;

// *.cpp
using cpp_callback = std::function<int(int a, int b)>;

// *.cpp
extern "C" 
double callback_wrapper(double a, double b, void* context) 
{
    auto& callback = *static_cast<cpp_callback*>(context);
    return (double) callback(a, b);
}

*/
