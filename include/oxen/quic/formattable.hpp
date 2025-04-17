#pragma once

#include <string_view>

namespace oxen::quic
{

    // Types can opt-in to being fmt-formattable by providing a ::to_string() method and a
    // static constexpr bool to_string_formattable = true.
    template <typename T>
    concept ToStringFormattable = T::to_string_formattable && requires(T a) {
        { a.to_string() } -> std::convertible_to<std::string_view>;
    };

}  // namespace oxen::quic
