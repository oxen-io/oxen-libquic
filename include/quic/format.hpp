#pragma once

#include <fmt/core.h>

#include <iostream>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

namespace oxen::quic
{
    // Types can opt-in to being formatting via .to_string() by specializing this to true
    template <typename T>
    constexpr bool IsToStringFormattable = false;

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
    template <>
    inline constexpr bool IsToStringFormattable<buffer_printer> = true;
}  // namespace oxen::quic

namespace fmt
{
    template <typename T>
    struct formatter<T, char, std::enable_if_t<oxen::quic::IsToStringFormattable<T>>> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(val.to_string(), ctx);
        }
    };

}  // namespace fmt
