#pragma once

// Optional header for formattable quic types; this header is not included automatically by any
// other quic header and must be included explicitly if wanted.  Using this header requires fmt be
// available (which is true in libquic itself, but may not be when libquic is installed as a
// library).

#include "formattable.hpp"
#include "utils.hpp"

#include <fmt/format.h>

#include <version>

namespace oxen::quic
{
    struct buffer_printer
    {
      private:
        std::span<const std::byte> buf;

      public:
        // string_view, C str literals, const string&:
        explicit buffer_printer(std::string_view data) : buf{reinterpret_span<const std::byte>(data)} {}

        // *Not* constructable from a string temporary because we only hold a view and do not take
        // ownership, and so the string will not survive until print time.
        explicit buffer_printer(std::string&& buf) = delete;

        // From byte span:
        explicit buffer_printer(std::span<const std::byte> data) : buf{data} {}
        explicit buffer_printer(std::span<const unsigned char> data) : buf{reinterpret_span<const std::byte>(data)} {}

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
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
