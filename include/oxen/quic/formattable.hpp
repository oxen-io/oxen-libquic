#pragma once

namespace oxen::quic
{

    // Types can opt-in to being fmt-formattable (by calling the .to_string() method when formatted)
    // by specializing this to true and the oxen/quic/format.hpp header.
    template <typename T>
    constexpr bool IsToStringFormattable = false;

}  // namespace oxen::quic
