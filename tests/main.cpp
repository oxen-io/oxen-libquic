#include "utils.hpp"

#include <catch2/catch_session.hpp>

bool oxen::quic::disable_ipv6, oxen::quic::disable_rotating_buffer, oxen::quic::disable_0rtt;

int main(int argc, char* argv[])
{
    Catch::Session session;

    using namespace Catch::Clara;
    std::string log_level = "critical", log_file = "stderr";
    bool test_case_tracing = false;
    oxen::quic::disable_ipv6 = false;
    oxen::quic::disable_rotating_buffer = false;

    auto cli =
            session.cli() | Opt(log_level, "level")["--log-level"]("oxen-logging log level to apply to the test run") |
            Opt(log_file, "file")["--log-file"](
                    "oxen-logging log file to output logs to, or one of  or one of stdout/-/stderr/syslog.") |
            Opt(oxen::quic::disable_ipv6)["--no-ipv6"]("disable ipv6 addressing in the test suite") |
            Opt(oxen::quic::disable_rotating_buffer)["--no-buf"]("disable rotating buffers in the test suite") |
            Opt(oxen::quic::disable_0rtt)["--disable-0rtt"]("disable 0rtt tests (especially for non-AMD64 debug builds)") |
            Opt(test_case_tracing)["-T"]["--test-tracing"]("enable oxen log tracing of test cases/sections");

    session.cli(cli);

    if (int rc = session.applyCommandLine(argc, argv); rc != 0)
        return rc;

    oxen::quic::setup_logging(log_file, log_level);

    oxen::log::set_level(oxen::log::Cat("testcase"), test_case_tracing ? oxen::log::Level::trace : oxen::log::Level::off);

    oxen::quic::test::defaults::CLIENT_KEYS = oxen::quic::generate_ed25519();
    oxen::quic::test::defaults::SERVER_KEYS = oxen::quic::generate_ed25519();

    return session.run();
}
