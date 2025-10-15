#include "connection_ids.hpp"

#include "format.hpp"
#include "internal.hpp"

#include <oxenc/hex.h>

#include <gnutls/crypto.h>

namespace oxen::quic
{

    std::string ConnectionID::to_string() const
    {
        return "< RID:{} >"_format(id);
    }

    std::string quic_cid::to_string() const
    {
        return oxenc::to_hex(_ngtcp2_cid.data, _ngtcp2_cid.data + _ngtcp2_cid.datalen);
    }

    quic_cid quic_cid::random()
    {
        quic_cid cid;
        cid._ngtcp2_cid.datalen = static_cast<size_t>(NGTCP2_MAX_CIDLEN);
        gnutls_rnd(GNUTLS_RND_RANDOM, cid._ngtcp2_cid.data, cid._ngtcp2_cid.datalen);
        return cid;
    }

}  // namespace oxen::quic
