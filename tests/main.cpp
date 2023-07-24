#include <catch2/catch_session.hpp>

#include "utils.hpp"

bool oxen::quic::disable_ipv6, oxen::quic::disable_rotating_buffer;

int main(int argc, char* argv[])
{
    Catch::Session session;

    using namespace Catch::Clara;
    std::string log_level = "trace", log_file = "stderr";
    oxen::quic::disable_ipv6 = false;
    oxen::quic::disable_rotating_buffer = false;

    auto cli = session.cli() | Opt(log_level, "level")["--log-level"]("oxen-logging log level to apply to the test run") |
               Opt(log_file, "file")["--log-file"](
                       "oxen-logging log file to output logs to, or one of  or one of stdout/-/stderr/syslog.") |
               Opt(oxen::quic::disable_ipv6)["--no-ipv6"]("disable ipv6 addressing in the test suite") |
               Opt(oxen::quic::disable_rotating_buffer)["--no-buf"]("disable rotating buffers in the test suite");

    session.cli(cli);

    if (int rc = session.applyCommandLine(argc, argv); rc != 0)
        return rc;

    oxen::quic::setup_logging(log_file, log_level);

    return session.run();
}
