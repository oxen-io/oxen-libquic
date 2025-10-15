#pragma once

#include <ngtcp2/ngtcp2.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>

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
    struct quic_cid
    {
      private:
        ngtcp2_cid _ngtcp2_cid{};

      public:
        quic_cid() = default;
        quic_cid(const quic_cid& c) = default;
        quic_cid(const ngtcp2_cid& c) : _ngtcp2_cid{c} {}
        quic_cid(const uint8_t* cid, size_t length)
        {
            assert(length <= NGTCP2_MAX_CIDLEN);
            _ngtcp2_cid.datalen = length;
            std::memcpy(_ngtcp2_cid.data, cid, length);
        }

        const ngtcp2_cid* ngtcp2() const { return &_ngtcp2_cid; }

        quic_cid& operator=(const quic_cid& c) = default;

        inline bool operator==(const quic_cid& other) const
        {
            return _ngtcp2_cid.datalen == other._ngtcp2_cid.datalen &&
                   std::memcmp(_ngtcp2_cid.data, other._ngtcp2_cid.data, _ngtcp2_cid.datalen) == 0;
        }

        inline bool operator!=(const quic_cid& other) const = default;

        static quic_cid random();

        inline size_t _hashed() const noexcept
        {
            static_assert(
                    alignof(quic_cid) >= alignof(size_t) && offsetof(quic_cid, _ngtcp2_cid) % sizeof(size_t) == 0 &&
                    offsetof(ngtcp2_cid, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(_ngtcp2_cid.data);
        }

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
        size_t operator()(const oxen::quic::quic_cid& cid) const noexcept { return cid._hashed(); }
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
