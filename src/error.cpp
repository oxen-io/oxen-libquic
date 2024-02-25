#include "error.hpp"

#include "internal.hpp"

namespace oxen::quic
{
    uint64_t io_error::ngtcp2() const
    {
        if (not is_ngtcp2)
            log::warning(log_cat, "Error code {} is not an ngtcp2 error code", _code);
        return _code;
    }
}  // namespace oxen::quic
