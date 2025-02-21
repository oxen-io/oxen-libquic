#include "gnutls_crypto.hpp"

#include "internal.hpp"

#include <nettle/sha3.h>

namespace oxen::quic
{
#ifdef NDEBUG
    void enable_gnutls_logging(int) {}
#else
    extern "C" void gnutls_log(int level, const char* str)
    {
        static auto cat = log::Cat("gnutls");
        std::string_view msg{str};
        if (msg.ends_with('\n'))
            msg.remove_suffix(1);
        cat->log(spdlog::source_loc{"LEVEL", level, "gnutls"}, log::Level::debug, "{}", msg);
    }

    void enable_gnutls_logging(int level)
    {
        gnutls_global_set_log_level(level);
        gnutls_global_set_log_function(gnutls_log);
    }
#endif

    void generate_reset_token(
            std::span<const uint8_t> static_secret,
            const ngtcp2_cid* cid,
            std::span<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> out)
    {
        if (ngtcp2_crypto_generate_stateless_reset_token(out.data(), static_secret.data(), static_secret.size(), cid) != 0)
            throw std::runtime_error{"Failed to generate stateless reset token!"};
    }
    void generate_reset_token(
            std::span<const uint8_t> static_secret,
            const quic_cid& cid,
            std::span<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> out)
    {
        generate_reset_token(static_secret, &cid, out);
    }
    std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> generate_reset_token(
            std::span<const uint8_t> static_secret, const ngtcp2_cid* cid)
    {
        std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token;
        generate_reset_token(static_secret, cid, token);
        return token;
    }
    std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> generate_reset_token(
            std::span<const uint8_t> static_secret, const quic_cid& cid)
    {
        return generate_reset_token(static_secret, &cid);
    }

    static constexpr auto STATELESS_HASH_PREFIX = "quic stateless reset hash"sv;
    hashed_reset_token::hashed_reset_token(
            std::span<const uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token, std::span<const uint8_t> static_secret)
    {
        // SHAKE256(STATELESS_HASH_PREFIX || static_secret || token)
        sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        sha3_256_update(&ctx, STATELESS_HASH_PREFIX.size(), reinterpret_cast<const uint8_t*>(STATELESS_HASH_PREFIX.data()));
        sha3_256_update(&ctx, static_secret.size(), static_secret.data());
        sha3_256_update(&ctx, token.size(), token.data());
        sha3_256_shake(&ctx, size(), data());
    }

}  //  namespace oxen::quic
