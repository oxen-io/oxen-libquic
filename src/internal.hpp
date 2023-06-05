#pragma once

#include <cstddef>

#include "utils.hpp"

namespace oxen::quic
{

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
            DATAGRAM_BATCH_SIZE;
#else
            1;
#endif

}  // namespace oxen::quic
