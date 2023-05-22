#pragma once

#include "utils.hpp"
#include "crypto.hpp"

#include <uvw.hpp>

#include <vector>
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
    class Client;
	class Server;
	class Network;
	class Connection;
    class ClientContext;
    class ServerContext;

	class Handler 
	{
		friend class Network;
		
		public:
			explicit Handler(std::shared_ptr<uvw::Loop> loop_ptr, Network& net);
			~Handler();

            Network& net;

            std::shared_ptr<uvw::UDPHandle> universal_handle;
            Address default_local{"127.0.0.1", 4433};
			std::shared_ptr<uvw::AsyncHandle> io_trigger;
            std::shared_ptr<uvw::Loop> ev_loop;

			std::shared_ptr<uvw::Loop>
    		loop();

			void
			client_call_async(async_callback_t async_cb);

            void
            client_close();

            void
            close_all();

        private:
			// Tracks client endpoints that are currently being managed by handler object
            std::vector<std::shared_ptr<ClientContext>> clients;
            // Maps server endpoints that are currently being managed by handler object
			//  - key: Address{local_addr}
			//  - value: pointer to server context object
			//
			// For example, when a user listens to 127.0.0.1:4433, the ClientManager ptr
			// will be indexed to Address{"127.0.0.1", "5440"}
            std::unordered_map<Address, std::shared_ptr<ServerContext>> servers;

			///	keep ev loop open for cleanup
			std::shared_ptr<int> keep_alive = std::make_shared<int>(0); 

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

Client: [server_cert, server_CA, system_CA, server_cert_callback] x [client_key/crt, no client key/cert]

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


API Usage Round 4:

    Network net{loop};

    auto c1 = net.client_connect(remote_addr{"127.0.0.1:4567"});
    auto c1a = net.client_connect(remote_addr{"127.0.0.1:4567"});
    auto c2 = net.client_connect(remote_addr{"127.0.0.2:2222"});

None of these specify a local bind address, so on the first call (when constructing c1) we would create an "any" UDPHandle

    auto c3 = net.client_connect(remote_addr{"127.0.0.3:5678"}, local_addr{"127.0.0.1:1111"});

This specifies an explicit local addr that has not been bound yet, so we create a new UDPHandle for it.

So somewhere in net we would have an unordered_map<local_addr, shared_ptr<UDPHandle>>, and when we need the UDPHandle we first 
check if we already have one for that local_addr (or for the "any" addr) and, if so, reuse it, otherwise construct a new one.



Just looking ahead a little bit: we're very likely going to want to support other types of buffers, too; we could make that generic 
by taking a const char* buf, size_t length, buf_free where buf_free is some callback we can call to free the associated buffer when 
done with it.  So then, for instance, if you had a std::vector<std::byte> on hand you could pass that using:
open_stream
    std::vector<std::byte> stuff = ...;
    {
        auto* buf = stuff.data();
        auto size = stuff.size();
        stream.send(buf, size, [stuff=std::move(stuff)] {});
    }

A better alternative to that lambda would be a std::any; so then there's nothing to call, libquiciness just 
destroys the any when it's done with the buffer. With bstring_view

    stream.send(bstring_view{stuff.data(), stuff.size()}, std::move(stuff));
    void send(bstring_view data, std::any keep_alive);


But yeah, ideally we would accept any old std::basic_string_view<Char> there
i.e. with something like:

    void send(bstring_view data, std::any keep_alive);
    template <typename Char, std::enable_if_t<sizeof(Char) == 1 && !std::is_same_v<Char, std::byte>, int> = 0>
    void send(std::basic_string_view<Char> data, std::any keep_alive) {
        return send(convert_sv<std::byte>(data), std::move(keep_alive));
    }

And maybe even some other options like:

    template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
    void send(std::vector<Char>&& buf) {
        return send(std::basic_string_view<Char>{buf.data(), buf.size()}, std::move(buf));
    }

So try_send would respect the buffer and refuse if it would get too big; send would be limit-ignoring.
    template <typename... Args>
    bool try_send(Args&&... data) {
        if (bytes_in_flight >= max_bytes_in_flight) return false;
        send(std::forward<Args>(args)...);
        return true;
    }


- implement something similar to blocked/unblocked s.t. we an signal a stream's local buffer is full.
    this is a parameter we can pass in stream creation, like "max_bytes_in_flight" or something
- use bstring_views with template logic to convert from the likely user types


- udppacket comes in, goes to handler
handler:
- decode's DCID from packet
- gets `net` out of user context
- calls net->consume(dcid, packet_data)


*/
