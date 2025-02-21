#pragma once

#include "formattable.hpp"
#include "types.hpp"

namespace oxen::quic
{
    // Unique reference ID for each individual connection. QUIC allows for a
    // connection to be reached at any of n number of connection ID's (see above
    // constexpr) at a time. As a result, we key each of those QUIC CID's to the
    // unique reference ID, to which the connection shared_ptr is keyed in the
    // master map container
    struct alignas(uint64_t) ConnectionID final
    {
        uint64_t id;

        ConnectionID() = delete;
        explicit ConnectionID(uint64_t v) : id{v} {}
        ConnectionID(const ConnectionID& obj) = default;
        ConnectionID(ConnectionID&& obj) = default;

        ConnectionID& operator=(const ConnectionID& obj) = default;
        ConnectionID& operator=(ConnectionID&& obj) = default;

        inline bool operator<(const ConnectionID& other) const { return id < other.id; }

        inline bool operator==(const ConnectionID& other) const { return id == other.id; }
        inline bool operator!=(const ConnectionID& other) const { return !(*this == other); }

        explicit operator const uint64_t&() const { return id; }

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };

    // Wrapper for ngtcp2_cid with helper functionalities to make it passable
    struct alignas(size_t) quic_cid final : ngtcp2_cid
    {
        quic_cid() = default;
        quic_cid(const quic_cid& c) = default;
        quic_cid(ngtcp2_cid c) : quic_cid(c.data, c.datalen) {}
        quic_cid(const uint8_t* cid, size_t length)
        {
            assert(length <= NGTCP2_MAX_CIDLEN);
            datalen = length;
            std::memmove(data, cid, datalen);
        }

        quic_cid& operator=(const quic_cid& c) = default;

        inline bool operator==(const quic_cid& other) const
        {
            return datalen == other.datalen && std::memcmp(data, other.data, datalen) == 0;
        }

        inline bool operator!=(const quic_cid& other) const { return !(*this == other); }

        static quic_cid random();

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };
}  // namespace oxen::quic

namespace std
{
    // Custom hash is required s.t. unordered_set storing ConnectionID:unique_ptr<quic_cid>
    // is able to call its implicit constructor
    template <>
    struct hash<oxen::quic::quic_cid>
    {
        size_t operator()(const oxen::quic::quic_cid& cid) const noexcept
        {
            static_assert(
                    alignof(oxen::quic::quic_cid) >= alignof(size_t) &&
                    offsetof(oxen::quic::quic_cid, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(cid.data);
        }
    };

    template <>
    struct hash<oxen::quic::ConnectionID>
    {
        size_t operator()(const oxen::quic::ConnectionID& rid) const noexcept
        {
            return std::hash<decltype(rid.id)>{}(rid.id);
        }
    };
}  // namespace std
