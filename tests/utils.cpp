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

}  // namespace oxen::quic
