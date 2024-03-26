#pragma once

// Optional header for formattable quic types; this header is not included automatically by any
// other quic header and must be included explicitly if wanted.  Using this header requires fmt be
// available (which is true in libquic itself, but may not be when libquic is installed as a
// library).

#include <fmt/format.h>

#include <iostream>

#include "formattable.hpp"

namespace oxen::quic
{
    struct buffer_printer
    {
        std::basic_string_view<std::byte> buf;

        // Constructed from any type of string_view<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(std::basic_string_view<T> buf) :
                buf{reinterpret_cast<const std::byte*>(buf.data()), buf.size()}
        {}

        // Constructed from any type of lvalue string<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(const std::basic_string<T>& buf) : buffer_printer(std::basic_string_view<T>{buf})
        {}

        // *Not* constructable from a string<T> rvalue (because we only hold a view and do not take
        // ownership).
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(std::basic_string<T>&& buf) = delete;

        // Constructable from a (T*, size) argument pair, for byte-sized T's.
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(const T* data, size_t size) : buffer_printer(std::basic_string_view<T>{data, size})
        {}

        std::string to_string() const;
    };
}  // namespace oxen::quic

namespace fmt
{
    template <oxen::quic::ToStringFormattable T>
    struct formatter<T, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(val.to_string(), ctx);
        }
    };
}  // namespace fmt
