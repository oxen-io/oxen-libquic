#include "speedtest-server.hpp"

#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <oxen/quic.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

#include "utils.hpp"

namespace oxen::quic::speedtest
{

    static auto cat = log::Cat("server");

    Server::Server(std::string seed_, quic::Address listen_) : seed{std::move(seed_)}, listen{std::move(listen_)}
    {
        try
        {
            log::debug(cat, "Starting up endpoint");
            endpoint = net.endpoint(listen, opt::enable_datagrams(Splitting::ACTIVE));
            endpoint->listen(
                    tls,
                    [&](Stream& s) {
                        log::warning(cat, "Stream {} opened!", s.stream_id());
                        return 0;
                    },
                    [this](Stream& s, bstring_view data) { on_stream_data(s, data); },
                    [this](dgram_interface& d, bstring_view data) { on_dgram_data(d, data); });
        }
        catch (const std::exception& e)
        {
            log::critical(cat, "Failed to start server: {}!", e.what());
            throw;
        }

        // We always want to see this log statement because it contains the pubkey the client needs,
        // but it feels wrong to force it to a critical statement, so temporarily lower the level to
        // info to display it.
        log_level_lowerer enable_info{log::Level::info, cat.name};
        std::vector<std::string> flags;
        if (listen != Address{"127.0.0.1", 5500})
            flags.push_back("--remote {}"_format(listen));
        flags.push_back("--remote-pubkey={}"_format(oxenc::to_base64(pubkey)));

        log::info(cat, "Listening on {}; client connection args:\n\t{}\n", listen, "{}"_format(fmt::join(flags, " ")));
    }

    void Server::on_stream_data(Stream& s, bstring_view data)
    {
        auto& sd = conn_stream_data[s.reference_id];

        auto it = sd.find(s.stream_id());
        if (it == sd.end())
        {
            if (data.size() < sizeof(uint64_t))
            {
                log::critical(cat, "Well this was unexpected: I got {} < 8 bytes", data.size());
                return;
            }

            auto size = oxenc::load_little_to_host<uint64_t>(data.data());
            data.remove_prefix(sizeof(uint64_t));

            it = sd.emplace(s.stream_id(), size).first;
            log::warning(cat, "First data from new stream {}, expecting {}B!", s.stream_id(), size);
        }

        auto& [ignore, info] = *it;

        bool need_more = info.received < info.expected;
        info.received += data.size();
        if (info.received > info.expected)
        {
            log::critical(cat, "Received too much data ({}B > {}B)!", info.received, info.expected);
            if (!need_more)
                return;
            data.remove_suffix(info.received - info.expected);
        }

        if (info.received >= info.expected)
        {
            log::warning(cat, "Data from stream {} complete ({} B).", s.stream_id(), info.received);

            s.send("DONE!"s);
        }
    }

    void Server::on_dgram_data(dgram_interface& di, bstring_view data)
    {
        auto& dgram_data = conn_dgram_data[di.reference_id];
        if (dgram_data.n_expected == 0)
        {
            // The very first packet should be 8 bytes containing the uint64_t count of total
            // packets being sent, not including this initial one.
            if (data.size() != 8)
                log::error(cat, "Invalid initial packet: expected 8-byte test size, got {} bytes", data.size());
            auto count = oxenc::load_little_to_host<uint64_t>(data.data());
            dgram_data.n_expected = count;
            log::warning(
                    cat, "First data from new connection datagram channel, expecting {} datagrams!", dgram_data.n_expected);
            return;
        }

        // Subsequent packets start with a \x00 until the final one; that has first byte set to \x01.
        const bool done = data[0] != std::byte{0};

        auto& info = dgram_data;
        bool need_more = info.n_received < info.n_expected;
        info.n_received += 1;

        if (info.n_received > info.n_expected)
        {
            log::critical(cat, "Received too many datagrams ({} > {})!", info.n_received, info.n_expected);

            if (!need_more)
                return;
        }

        if (done)
        {
            auto reception_rate = ((float)info.n_received / (float)info.n_expected) * 100;

            log::critical(
                    cat,
                    "Datagram test complete. Fidelity: {}\% ({} received of {} expected)",
                    reception_rate,
                    info.n_received,
                    info.n_expected);

            di.reply("DONE-{}"_format(info.n_received));
        }
    }

}  // namespace oxen::quic::speedtest
