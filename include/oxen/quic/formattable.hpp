#pragma once

namespace oxen::quic
{
    // Types can opt-in to being fmt-formattable by ensuring they have a ::to_string() method defined
    template <typename T>
    concept
#if (!(defined(__clang__)) && defined(__GNUC__) && __GNUC__ < 10)
            bool
#endif
                    ToStringFormattable = requires(T a)
    {
        a.to_string();
    };
}  // namespace oxen::quic
