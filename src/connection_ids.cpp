#include "connection_ids.hpp"

#include <oxenc/hex.h>

#include "format.hpp"
#include "internal.hpp"

namespace oxen::quic
{

    std::string ConnectionID::to_string() const
    {
        return "< RID:{} >"_format(id);
    }

    std::string quic_cid::to_string() const
    {
        return oxenc::to_hex(data, data + datalen);
    }

}  // namespace oxen::quic
