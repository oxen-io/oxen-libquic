#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <memory>
#include <type_traits>
#include <unordered_map>

#include "utils.hpp"

namespace fs = std::filesystem;

namespace oxen::quic
{
    namespace opt
    {
        struct client_tls;
        struct server_tls;
    }  // namespace opt

    enum context_init_scheme { SERVER = 0, CLIENT = 1 };

    // Struct to wrap cert/key information. Can hold either a string-path, gnutls_datum of the
    // actual key or cert, plus extension and type info.
    // Passable as:
    //      - const char* (ex: to gnutls_certificate_set_x509_key_file)
    //      - gnutls_datum_t* (ex: to gnutls_certificate_set_x509_trust_dir)
    //      - gnutls_x509_crt_fmt_t (ex: to parameter 3 of the above functions)
    struct datum
    {
        fs::path path{};
        gnutls_datum_t mem{};
        gnutls_x509_crt_fmt_t ext{};
        bool from_mem{false};

        datum() = default;
        datum(std::string input) : path{input}
        {
            if (fs::exists(path))
            {
                ext = (str_tolower(path.extension()) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                mem.data = nullptr;
                mem.size = 0;
            }
            else
            {
                path = NULL;
                mem = {(uint8_t*)input.data(), (uint8_t)input.size()};
                ext = !("-----"s.compare(input.substr(0, 5))) ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                from_mem = true;
            }
        }
        datum(datum const& other)
        {
            if (!other.path.empty())
                path = other.path;
            memcpy(mem.data, other.mem.data, other.mem.size);
            mem.size = other.mem.size;
            if (ext)
                ext = other.ext;
            from_mem = other.from_mem;
        }

        // returns truew if path is not empty OR mem has a value set
        inline explicit operator bool() const noexcept { return (!path.empty() || mem.size); }

        operator const char*() { return path.c_str(); }
        operator const gnutls_datum_t*() { return &mem; }
        operator gnutls_x509_crt_fmt_t() { return ext; }
    };

    // Pure virtual TLSContext base class; Derived classes manage all pinned TLS certificates and
    // wrap system's root CA trust
    struct TLSContext
    {
        ngtcp2_crypto_conn_ref conn_ref;
        gnutls_session_t session;
        virtual ~TLSContext() = default;
    };

    // Pure virtual TLSCert base class
    struct TLSCert
    {
        virtual ~TLSCert() = default;
        virtual std::shared_ptr<TLSContext> into_context() && = 0;
    };

    // Null certificate for unsecured connections
    struct NullCert : TLSCert
    {
        std::shared_ptr<TLSContext> into_context() && override;
    };

    struct GNUTLSCert : TLSCert
    {
        datum private_key{};
        datum local_cert{};
        datum remote_cert{};  // if client, this is server cert and vice versa
        datum remote_ca{};    // if client, this is server CA and vice versa
        server_tls_callback_t server_tls_cb;
        client_tls_callback_t client_tls_cb;
        gnutls_certificate_credentials_t cred;
        context_init_scheme scheme;

        GNUTLSCert() = default;

        // called by server for subsequent connections
        GNUTLSCert(GNUTLSCert const& other) :
                private_key{other.private_key},
                local_cert{other.local_cert},
                remote_ca{other.remote_ca},
                remote_cert{other.remote_cert},
                cred{other.cred},
                scheme{other.scheme}
        {
            log::trace(log_cat, "GNUTLSCert copy constructor");
        }

        // direct construction from opt types
        explicit GNUTLSCert(opt::client_tls client_tls);
        explicit GNUTLSCert(opt::server_tls server_tls);

        std::shared_ptr<TLSContext> into_context() && override;

        int _client_cred_init();
        int _server_cred_init();
    };

    // GnuTLS certificate context
    struct GNUTLSContext : TLSContext
    {
        explicit GNUTLSContext(GNUTLSCert cert) : gcert{cert}
        {
            log::trace(log_cat, "Initializing GNUTLSContext with scheme: {}", (int)gcert.scheme);

            switch (gcert.scheme)
            {
                case SERVER:
                    log::debug(log_cat, "Commencing server session initialization");
                    _server_session_init();
                    break;
                case CLIENT:
                    log::debug(log_cat, "Commencing client session initialization");
                    _client_session_init();
                    break;
                default:
                    log::warning(log_cat, "GNUTLSContext initialization failed: scheme not recognized");
                    break;
            }
        };

        ~GNUTLSContext();

        gnutls_priority_t priority;
        gnutls_x509_crt_int* cert;
        server_tls_callback_t server_tls_cb;
        client_tls_callback_t client_tls_cb;
        GNUTLSCert gcert;

        void client_callback_init();
        void server_callback_init();

      private:
        int _client_session_init();
        int _server_session_init();
    };

    // Null certificate context
    struct NullContext : TLSContext
    {
        explicit NullContext(NullCert ncert) : cert{ncert} {};

        NullCert cert;
    };

    extern "C"
    {
        int server_cb_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* ms);
        int client_cb_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* ms);
        int server_protocol_hook(
                gnutls_session_t session,
                unsigned int type,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg);
    }

}  // namespace oxen::quic
