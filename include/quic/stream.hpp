#pragma once

#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <uvw.hpp>

#include <queue>
#include <any>
#include <variant>
#include <functional>
#include <cassert>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <deque>


namespace oxen::quic
{
	class Connection;
	class Stream;
    
	using stream_data_callback_t = std::function<void(Stream&, bstring_view)>;
	using stream_close_callback_t = std::function<void(Stream&, uint64_t error_code)>;
	using unblocked_callback_t = std::function<bool(Stream&)>;

	// One-shot datagram sent inside a quic connection
	struct DatagramBuffer
	{
		public:
			// Write buffer for outgoing packets
			std::vector<std::byte> buf;

            // Returns number of bits written to buffer
			size_t
			size() const { return buf.size(); }

			explicit DatagramBuffer(size_t size = 1200)
			{
				buf.reserve(size);
                nwrote = 0;
                remaining = size;
			}

			~DatagramBuffer()
			{
				std::memset(&buf, 0, buf.size());
                buf.clear();
			}

			DatagramBuffer&
			operator=(const DatagramBuffer& d)
			{
                assert(d.size() <= size());
                std::memcpy(buf.data(), d.buf.data(), d.size());
                return *this;
			}

            size_t
            write(const char* data, size_t nbits);

		private:
			///	Bits written to buffer
			size_t nwrote;
            size_t remaining;
	};


	class Stream : public std::enable_shared_from_this<Stream>
	{
		public:
			explicit Stream(Connection& conn, size_t bufsize, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr, int64_t stream_id = -1);
			explicit Stream(Connection& conn, size_t bufsize, int64_t stream_id = -1);
			~Stream();

			stream_data_callback_t data_callback;
			stream_close_callback_t close_callback;
			Connection& conn;

			int64_t stream_id{-1};
			std::shared_ptr<uvw::UDPHandle> udp_handle;
			std::vector<uint8_t> data;
			size_t datalen;
			size_t nwrite;
			
            std::deque<std::pair<bstring_view, std::any>> user_buffers;

			Connection&
			get_conn();

			void
			close(uint64_t error_code = 0);

			void
			io_ready();

			void
			available_ready();

			void
			wrote(size_t bytes);

			void
			when_available(unblocked_callback_t unblocked_cb);

			void
			append_buffer(const std::byte* buffer, size_t length);

			void
			acknowledge(size_t bytes);

			inline size_t
			available() const
			{ return is_closing || user_buffers.empty() ? 0 : user_buffers.size() - size; }

			inline size_t
			used() const
			{ return size; }

			inline size_t
			unacked() const
			{ return unacked_size; }

			inline size_t
			unsent() const
			{ return used() - unacked(); }

			// Retrieve stashed data with static cast to desired type
			template <typename T>
			std::shared_ptr<T>
			get_user_data() const
			{ return std::static_pointer_cast<T>(user_data); }

			void
			set_user_data(std::shared_ptr<void> data);

            void 
            send(bstring_view data, std::any keep_alive);

            template <
                typename CharType, 
                std::enable_if_t<sizeof(CharType) == 1 && !std::is_same_v<CharType, std::byte>, int> = 0>
            void 
            send(std::basic_string_view<CharType> data, std::any keep_alive) 
            {
                return send(convert_sv<std::byte>(data), std::move(keep_alive));
            }

            template <
                typename Char, 
                std::enable_if_t<sizeof(Char) == 1, int> = 0>
            void 
            send(std::vector<Char>&& buf) 
            {
                return send(std::basic_string_view<Char>{buf.data(), buf.size()}, std::move(buf));
            }
		
		private:
			friend class Connection;

			// Callback(s) to invoke once we have the requested amount of space available in the buffer.
			std::queue<unblocked_callback_t> unblocked_callbacks;
			void
			handle_unblocked();  // Processes the above if space is available


			std::vector<bstring_view>
			pending();

			size_t size{0};
			size_t start{0};
			size_t unacked_size{0};
            size_t max_bufsize{0};

			bool is_new{false};
			bool is_closing{false};
			bool is_shutdown{false};
			bool sent_fin{false};

			// Async trigger for batch scheduling callbacks
			std::shared_ptr<uvw::AsyncHandle> avail_trigger;

            // TOTHINK: maybe should store a ptr to network or handler here?
			std::shared_ptr<void> user_data;
	};
}	// namespace oxen::quic
