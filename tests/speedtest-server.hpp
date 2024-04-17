#include <memory>
#include <oxen/quic/address.hpp>
#include <string>
#include <unordered_map>

#include "utils.hpp"

namespace oxen::quic::speedtest
{

    class Server
    {
      private:
        struct stream_info
        {
            explicit stream_info(uint64_t expected) : expected{expected} {}

            uint64_t expected;
            uint64_t received = 0;
        };

        struct recv_info
        {
            uint64_t n_expected = 0;
            uint64_t n_received = 0;
        };

        std::unordered_map<ConnectionID, std::unordered_map<int64_t, stream_info>> conn_stream_data;
        std::unordered_map<ConnectionID, recv_info> conn_dgram_data;

      public:
        std::string seed;
        std::string pubkey = make_keypair(seed);
        quic::Address listen;
        Network net;

      private:
        std::shared_ptr<GNUTLSCreds> tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
        std::shared_ptr<Endpoint> endpoint;

        void on_stream_data(Stream& s, bstring_view data);
        void on_dgram_data(dgram_interface& di, bstring_view data);

      public:
        Server(std::string seed_, quic::Address listen_);
    };

}  // namespace oxen::quic::speedtest
