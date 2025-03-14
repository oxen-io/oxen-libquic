#pragma once

// IWYU pragma: begin_exports

#include "utils.hpp"

#include <oxenc/span.h>

// keep above Catch2 includes to get comparators
using namespace oxenc::operators;

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
    template <oxenc::const_span_type SpanT>
    struct SpanEqualsMatcher : Catch::Matchers::MatcherGenericBase
    {
      private:
        const SpanT& s;

      public:
        SpanEqualsMatcher(const SpanT& _s) : s{_s} {}

        bool match(const SpanT& other) const { return std::ranges::equal(s, other); }

        std::string describe() const override { return "Equals: {}"_format(sp_to_sv(s)); }
    };

    template <oxenc::const_span_type SpanT>
    auto EqualsSpan(const SpanT& T) -> SpanEqualsMatcher<SpanT>
    {
        return SpanEqualsMatcher<SpanT>{T};
    }

}  // namespace oxen::quic
