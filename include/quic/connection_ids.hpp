#pragma once

#include <stdexcept>

extern "C"
{
#include <gnutls/crypto.h>
}

#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    // Unique reference ID for each individual connection. QUIC allows for a
    // connection to be reached at any of n number of connection ID's (see above
    // constexpr) at a time. As a result, we key each of those QUIC CID's to the
    // unique reference ID, to which the connection shared_ptr is keyed in the
    // master map container
    struct alignas(uint64_t) ReferenceID final
    {
      private:
        uint64_t id;

      public:
        ReferenceID() = delete;
        ReferenceID(uint64_t v) : id{v} {}
        ReferenceID(const ReferenceID& obj) = default;
        ReferenceID(ReferenceID&& obj) = default;
        ReferenceID& operator=(const ReferenceID& obj) = default;
        ReferenceID& operator=(ReferenceID&& obj) = default;

        operator const uint64_t&() const { return id; }
        // operator uint64_t&() { return id; }

        std::string to_string() const { return "< RID:{} >"_format(id); }
    };
    template <>
    constexpr inline bool IsToStringFormattable<ReferenceID> = true;

    // Wrapper for ngtcp2_cid with helper functionalities to make it passable
    struct alignas(size_t) ConnectionID final : ngtcp2_cid
    {
        ConnectionID() = default;
        ConnectionID(const ConnectionID& c) = default;
        ConnectionID(ngtcp2_cid c) : ConnectionID(c.data, c.datalen) {}
        ConnectionID(const uint8_t* cid, size_t length)
        {
            assert(length <= NGTCP2_MAX_CIDLEN);
            datalen = length;
            std::memmove(data, cid, datalen);
        }

        ConnectionID& operator=(const ConnectionID& c) = default;

        inline bool operator==(const ConnectionID& other) const
        {
            return datalen == other.datalen && std::memcmp(data, other.data, datalen) == 0;
        }
        inline bool operator!=(const ConnectionID& other) const { return !(*this == other); }
        static ConnectionID random()
        {
            ConnectionID cid;
            cid.datalen = static_cast<size_t>(NGTCP2_MAX_CIDLEN);
            gnutls_rnd(GNUTLS_RND_RANDOM, cid.data, cid.datalen);
            return cid;
        }

        std::string to_string() const
        {
            return "{:02x}"_format(fmt::join(std::begin(data), std::begin(data) + datalen, ""));
        }
    };
    template <>
    constexpr inline bool IsToStringFormattable<ConnectionID> = true;
}  // namespace oxen::quic

namespace std
{
    // Custom hash is required s.t. unordered_set storing ConnectionID:unique_ptr<Connection>
    // is able to call its implicit constructor
    template <>
    struct hash<oxen::quic::ConnectionID>
    {
        size_t operator()(const oxen::quic::ConnectionID& cid) const
        {
            static_assert(
                    alignof(oxen::quic::ConnectionID) >= alignof(size_t) &&
                    offsetof(oxen::quic::ConnectionID, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(cid.data);
        }
    };
}  // namespace std
