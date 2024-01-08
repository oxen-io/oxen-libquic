#include "utils.hpp"

#include <nettle/eddsa.h>

namespace oxen::quic
{

    std::pair<std::shared_ptr<GNUTLSCreds>, std::shared_ptr<GNUTLSCreds>> test::defaults::tls_creds_from_ed_keys()
    {
        auto client = GNUTLSCreds::make_from_ed_keys(CLIENT_SEED, CLIENT_PUBKEY);
        auto server = GNUTLSCreds::make_from_ed_keys(SERVER_SEED, SERVER_PUBKEY);

        return std::make_pair(std::move(client), std::move(server));
    }

    std::pair<std::string, std::string> generate_ed25519()
    {
        std::pair<std::string, std::string> result;
        auto& [seed, pubkey] = result;
        seed.resize(32);
        pubkey.resize(32);

        gnutls_rnd(gnutls_rnd_level_t::GNUTLS_RND_KEY, seed.data(), sizeof(seed.size()));
        ed25519_sha512_public_key(
                reinterpret_cast<unsigned char*>(pubkey.data()), reinterpret_cast<const unsigned char*>(seed.data()));

        return result;
    }

    void add_log_opts(CLI::App& cli, std::string& file, std::string& level)
    {
        file = "stderr";
        level = "debug";

        cli.add_option("-l,--log-file", file, "Log output filename, or one of stdout/-/stderr/syslog.")
                ->type_name("FILE")
                ->capture_default_str();

        cli.add_option("-L,--log-level", level, "Log verbosity level; one of trace, debug, info, warn, error, critical, off")
                ->type_name("LEVEL")
                ->capture_default_str()
                ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "critical", "off"}));
    }

    void setup_logging(std::string out, const std::string& level)
    {
        log::Level lvl = log::level_from_string(level);

        constexpr std::array print_vals = {"stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};
        log::Type type;
        if (std::count(print_vals.begin(), print_vals.end(), out))
            type = log::Type::Print;
        else if (out == "syslog")
            type = log::Type::System;
        else
            type = log::Type::File;

        logger_config(out, type, lvl);
    }

    std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port)
    {
        std::pair<std::string, uint16_t> result;
        if (auto p = addr.find_last_not_of("0123456789");
            p != std::string_view::npos && p + 2 <= addr.size() && addr[p] == ':')
        {
            if (!parse_int(addr.substr(p + 1), result.second))
                throw std::invalid_argument{"Invalid address: could not parse port"};
            addr.remove_suffix(addr.size() - p);
        }
        else if (default_port)
        {
            result.second = *default_port;
        }
        else
        {
            throw std::invalid_argument{"Invalid address: no port was specified and there is no default"};
        }

        bool had_sq_brackets = false;
        if (!addr.empty() && addr.front() == '[' && addr.back() == ']')
        {
            addr.remove_prefix(1);
            addr.remove_suffix(1);
            had_sq_brackets = true;
        }

        if (auto p = addr.find_first_not_of("0123456789."); p != std::string_view::npos)
        {
            if (auto q = addr.find_first_not_of("0123456789abcdef:."); q != std::string_view::npos)
                throw std::invalid_argument{"Invalid address: does not look like IPv4 or IPv6!"};
            else if (!had_sq_brackets)
                throw std::invalid_argument{"Invalid address: IPv6 addresses require [...] square brackets"};
        }

        if (addr.empty())
            addr = "::";

        result.first = addr;
        return result;
    }

}  // namespace oxen::quic
