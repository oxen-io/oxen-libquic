#pragma once

// IWYU pragma: begin_exports

#include "utils.hpp"

#include <oxenc/common.h>

// keep above Catch2 includes to get comparators

#include <catch2/catch_test_case_info.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_templated.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

// IWYU pragma: end_exports

namespace oxen::quic
{
    template <oxenc::basic_char Char>
    std::span<const Char> to_span(std::string_view x)
    {
        return {reinterpret_cast<const Char*>(x.data()), x.size()};
    }
    inline std::string_view view(std::span<const unsigned char> x)
    {
        return {reinterpret_cast<const char*>(x.data()), x.size()};
    }
    inline std::string_view view(std::span<const std::byte> x)
    {
        return {reinterpret_cast<const char*>(x.data()), x.size()};
    }
    inline std::string_view view(std::span<const char> x)
    {
        return {x.data(), x.size()};
    }
}  // namespace oxen::quic
