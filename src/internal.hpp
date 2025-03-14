#pragma once

// IWYU pragma: begin_exports
#include "format.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include <fmt/format.h>

#include <cstddef>
#include <cstdint>

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    namespace log = oxen::log;

    using namespace log::literals;
    using namespace oxenc::literals;

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
            DATAGRAM_BATCH_SIZE;
#else
            1;
#endif

}  // namespace oxen::quic

// IWYU pragma: end_exports
