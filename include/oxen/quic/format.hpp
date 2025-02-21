#pragma once

// Optional header for formattable quic types; this header is not included automatically by any
// other quic header and must be included explicitly if wanted.  Using this header requires fmt be
// available (which is true in libquic itself, but may not be when libquic is installed as a
// library).

#include "formattable.hpp"
#include "utils.hpp"

#include <oxenc/span.h>

#include <fmt/format.h>

#include <iostream>
#include <version>

namespace oxen::quic
{
    struct buffer_printer
    {
      private:
        bspan buf;

      public:
        template <oxenc::basic_char T>
        explicit buffer_printer(const T* data, size_t datalen) : buf{reinterpret_cast<const std::byte*>(data), datalen}
        {}

        // Constructed from any type of string_view<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <oxenc::basic_char T>
        explicit buffer_printer(std::basic_string_view<T> data) : buffer_printer{data.data(), data.size()}
        {}

        // Constructed from any type of lvalue string<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <oxenc::basic_char T>
        explicit buffer_printer(const std::basic_string<T>& data) : buffer_printer{data.data(), data.size()}
        {}

        // *Not* constructable from a string<T> rvalue (because we only hold a view and do not take
        // ownership).
        template <oxenc::basic_char T>
        explicit buffer_printer(std::basic_string<T>&& buf) = delete;

        // Constructed from any type of span
        template <oxenc::const_span_type T>
        explicit buffer_printer(const T& data) : buffer_printer{data.data(), data.size()}
        {}

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };
}  // namespace oxen::quic

namespace fmt
{
    template <oxen::quic::concepts::ToStringFormattable T>
    struct formatter<T, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(val.to_string(), ctx);
        }
    };

    template <>
    struct formatter<oxen::quic::cspan, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const oxen::quic::cspan& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format({val.data(), val.size()}, ctx);
        }
    };
}  // namespace fmt
