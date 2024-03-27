#pragma once

#include "address.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class DatagramIO;

    enum class dgram { STANDARD = 0, OVERSIZED = 1 };

    struct outbound_dgram
    {
        bstring_view data;
        uint16_t id;
        // -1: payload, 1: addendum
        int8_t type{0};
        // is the datagram_storage container empty after sending this payload?
        bool is_empty{false};
    };

    struct prepared_datagram
    {
        uint64_t id;                  // internal ID for ngtcp2
        std::array<uint8_t, 2> dgid;  // optional transmitted ID buffer (for packet splitting)
        std::array<ngtcp2_vec, 2> bufs;
        size_t bufs_len;  // either 1 or 2 depending on how much of data is populated
        // is the datagram_storage container empty after sending this payload?
        bool is_empty{false};

        const ngtcp2_vec* data() const { return bufs.data(); }
        size_t size() const { return bufs_len; }
    };

    struct received_datagram
    {
        uint16_t id{0};
        // -1 = payload, 1 = addendum
        int8_t part{0};
        uint16_t data_size{0};
        std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD> data;

        received_datagram() = default;
        explicit received_datagram(uint16_t dgid, bstring_view d) :
                id{dgid}, part{(dgid % 4 == 2) ? int8_t{-1} : int8_t{1}}, data_size{static_cast<uint16_t>(d.size())}
        {
            std::memcpy(data.data(), d.data(), data_size);
        }
    };

    struct datagram_storage
    {
        uint16_t pload_id;
        std::optional<uint16_t> add_id;
        std::optional<bstring_view> payload, addendum;
        std::shared_ptr<void> keep_alive;
        dgram type;

        static datagram_storage make(
                bstring_view pload, uint16_t d_id, std::shared_ptr<void> data, dgram type, size_t max_size = 0);

        bool empty() const { return !(payload || addendum); }

        outbound_dgram fetch(bool b);

        size_t size() const { return payload->length() + addendum->length(); }

      private:
        explicit datagram_storage(bstring_view pload, uint16_t p_id, std::shared_ptr<void> data) :
                pload_id{p_id}, payload{pload}, keep_alive{std::move(data)}, type{dgram::STANDARD}
        {}

        explicit datagram_storage(
                bstring_view pload, bstring_view add, uint16_t p_id, uint16_t a_id, std::shared_ptr<void> data) :
                pload_id{p_id},
                add_id{a_id},
                payload{pload},
                addendum{add},
                keep_alive{std::move(data)},
                type{dgram::OVERSIZED}
        {}
    };

    struct rotating_buffer
    {
        int row{0}, col{0}, last_cleared{-1};
        DatagramIO& datagram;
        const int bufsize;
        const int rowsize;
        // tracks the number of partial datagrams held in each buffer bucket
        std::array<int, 4> currently_held{0, 0, 0, 0};

        explicit rotating_buffer() = delete;
        explicit rotating_buffer(DatagramIO& _d);

        std::array<std::vector<std::unique_ptr<received_datagram>>, 4> buf;

        std::optional<bstring> receive(bstring_view data, uint16_t dgid);
        void clear_row(int index);
        int datagrams_stored() const;
    };

    struct buffer_que
    {
        std::deque<datagram_storage> buf{};

        bool empty() const { return buf.empty(); }
        size_t size() const { return buf.size(); }

        void drop_front(bool b);

        prepared_datagram prepare(bool b, int is_splitting);

        void emplace(bstring_view pload, uint16_t p_id, std::shared_ptr<void> data, dgram type, size_t max_size = 0);
    };

}  // namespace oxen::quic
