#include "result.hpp"

#include "internal.hpp"

namespace oxen::quic
{
    uint64_t io_error::ngtcp2() const
    {
        if (not is_ngtcp2)
            log::warning(log_cat, "Error code {} is not an ngtcp2 error code", _code);
        return _code;
    }

    std::string quic_strerror(uint64_t e)
    {
        switch (e)
        {
            case 0:
                return "No error"s;
            case DATAGRAM_ERROR_EXCEPTION:
                return "Error - datagram exception"s;
            case STREAM_ERROR_EXCEPTION:
                return "Error - stream exception"s;
            case BPARSER_ERROR_EXCEPTION:
                return "Error - bt request stream exception"s;
            case STREAM_ERROR_CONNECTION_CLOSED:
                return "Error - stream connection closed"s;
            case CONN_WRITE_CLOSE_FAIL:
                return "Error - Failed to write connection close"s;
            case CONN_SEND_CLOSE_FAIL:
                return "Error - Failed to send connection close"s;
            case CONN_SEND_FAIL:
                return "Error - Failed to send packet"s;
            case CONN_IDLE_CLOSED:
                return "Connection closed by idle timeout"s;
            default:
                return "Application error code {}"_format(e);
        }
    }

    std::string io_error::strerror() const
    {
        return is_ngtcp2 ? ngtcp2_strerror(static_cast<int>(_code)) : quic_strerror(_code);
    }

    std::conditional_t<IN_HELL, std::string, std::string_view> io_result::str_error() const
    {
#ifdef _WIN32
        if (is_wsa)
        {
            std::array<char, 256> buf;
            buf[0] = 0;

            FormatMessage(
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr,
                    error_code,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    buf.data(),
                    buf.size(),
                    nullptr);
            if (buf[0])
                return buf.data();
            return "Unknown error "s.append(std::to_string(error_code));
        }
#endif
        if (is_ngtcp2)
            return ngtcp2_strerror(error_code);

        return strerror(error_code);
    }

}  // namespace oxen::quic
