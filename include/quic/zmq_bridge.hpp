#pragma once

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "connection.hpp"
#include "datagram.hpp"

namespace oxen::quic
{
    const std::chrono::milliseconds heartbeat{
#ifndef NDEBUG
            5
#else
            100
#endif
    };
    const std::chrono::milliseconds heartbeat_expiry{
#ifndef NDEBUG
            10
#else
            300
#endif
    };
    const std::chrono::milliseconds timeout{
#ifndef NDEBUG
            15
#else
            300
#endif
    };

    template <typename ztype>
    struct io_buffer
    {
        std::list<ztype> data;

        inline bool empty() const { return data.empty(); }
        inline void pop() { data.pop_front(); }
    };

    class ZMQChannel : public UserChannelBase
    {
        friend class ZMQBridge;

      public:
        std::unique_ptr<zmq::socket_t> wsock;

        std::thread worker_thread;

        zmq::pollitem_t worker_poll;

        io_buffer<zmq::message_t> buf;

        const ConnectionID scid;

        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point next_heartbeat;

        static std::shared_ptr<ZMQChannel> make(Endpoint& e, Connection& c, zmq::context_t& _ctx, zmq::socket_t&)
        {
            auto zw = std::shared_ptr<ZMQChannel>(new ZMQChannel{e, c});
            zw->initialize();
            return zw;
        }

        ~ZMQChannel() { close(); }

        void close()
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (active)
            {
                active = false;

                if (worker_thread.joinable())
                    worker_thread.join();

                wsock.reset();
            }
        }

      private:
        ZMQChannel(Endpoint& e, Connection& c) :
                UserChannelBase{c, e}, scid{conn.scid()}
        {
            // wsock = std::make_unique<zmq::socket_t>(_ctx, zmq::socket_type::router);
        }

        bool active;

        void initialize() override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            std::promise<void> p;
            auto f = p.get_future();

            worker_thread = std::thread{&ZMQChannel::worker_loop, this, std::move(p)};

            log::trace(log_cat, "Waiting on worker thread...");
            f.get();
            log::trace(log_cat, "Worker thread active!");
        }

        void worker_loop(std::promise<void> p)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            try
            {
                log::trace(log_cat, "Binding worker socket...");
                wsock->bind("inproc://worker"s + conn.scid().to_string());
                wsock->set(zmq::sockopt::router_mandatory, true);
                wsock->set(zmq::sockopt::linger, 0);

                worker_poll.socket = static_cast<void*>(*wsock);
                worker_poll.events = ZMQ_POLLIN;
                worker_poll.fd = 0;
            }
            catch (std::exception& e)
            {
                p.set_exception(std::current_exception());
                log::error(log_cat, "Exception caught in worker loop initialization: {}", e.what());
                return;
            }

            active = true;
            p.set_value();

            start_time = get_time();
            next_heartbeat = start_time + heartbeat;

            while (true)
            {
                if (active)
                {
                    if (auto rv = zmq::poll(&worker_poll, 1, timeout); rv > 0)
                    {
                        if (auto r = zmq::recv_multipart(*wsock, std::back_inserter(buf.data)); r)
                        {
                            log::trace(log_cat, "Worker received {}-part message", *r);

                            // do something with it now
                        }
                    }
                }
                else
                {
                    log::debug(log_cat, "Worker (CID: {}) exiting worker loop...", scid);
                    break;
                }
            }
        }

        // Inherited virtual methods
        bool is_stream() const override { return false; }
        bool is_empty() const override { return false; }
        std::shared_ptr<Stream> get_stream() override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return nullptr;
        }
        int64_t stream_id() const override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return std::numeric_limits<int64_t>::min();
        };
        bool is_closing() const override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return false;
        };
        bool sent_fin() const override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return false;
        };
        void set_fin(bool) override { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); };
        size_t unsent() const override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return {};
        };
        bool has_unsent() const override { return not is_empty(); }
        void wrote(size_t) override { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); };
        std::vector<ngtcp2_vec> pending() override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return {};
        };
        void send(bstring_view, std::shared_ptr<void> = nullptr) override
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            throw std::runtime_error{"ZMQ worker should not be directly calling virtual methods"};
        };
        prepared_datagram pending_datagram(bool) override
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            throw std::runtime_error{"Stream objects should not be queried for pending datagrams!"};
        }
    };

    class ZMQBridge
    {
        Endpoint& endpoint;
        zmq::context_t ctx;

        zmq::socket_t broker;   // router socket
        zmq::socket_t command;  // router socket

        std::thread broker_thread;

        zmq::pollitem_t broker_poll;
        zmq::pollitem_t command_poll;

        io_buffer<zmq::message_t> frontend_buf;  // receives incoming requests from sender
        io_buffer<zmq::message_t> backend_buf;   // receives incoming responses from workers

        // Internal mapping of active workers, 1:1 with quic::Connections
        //  key: scid of housing connection
        //  value: ZMQWorker paired with connection
        std::unordered_map<ConnectionID, std::shared_ptr<ZMQChannel>> workers;

        // Mapping of worker dealer sockets, keyed to the ConnectionID of the quic::Connection
        // they are emplaced into. ZMQWorkers hold a socket_ref to this socket
        std::unordered_map<ConnectionID, zmq::socket_t> worker_sockets;

        size_t num_workers{0};

        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point next_heartbeat;

      public:
        static std::unique_ptr<ZMQBridge> make(Endpoint& e)
        {
            auto z = std::unique_ptr<ZMQBridge>{new ZMQBridge(e)};
            z->initialize();
            return z;
        }

        std::shared_ptr<ZMQChannel> deploy_worker(Connection& c)
        {
            auto scid = c.scid();

            // create and configure worker socket
            auto ws = zmq::socket_t(ctx, zmq::socket_type::dealer);
            ws.set(zmq::sockopt::routing_id, scid.to_string());
            ws.set(zmq::sockopt::linger, 0);
            ws.connect(command.get(zmq::sockopt::last_endpoint));

            // emplace worker socket used to phone home
            worker_sockets.emplace(scid, std::move(ws));

            auto [w_itr, r] = workers.emplace(scid, nullptr);

            w_itr->second = ZMQChannel::make(endpoint, c, ctx, ws);
            w_itr->second->initialize();

            num_workers += 1;

            return w_itr->second;
        }

        void close_worker(ConnectionID target)
        {
            if (workers[target].get())
            {
                log::trace(log_cat, "Worker paired to CID: {} closing...", target);
                workers.erase(target);

                auto& ws = worker_sockets.at(target);
                ws.close();
                worker_sockets.erase(target);
                log::debug(log_cat, "Worker paired to CID: {} closed!", target);

                num_workers -= 1;
            }
            else
                log::debug(log_cat, "Could not find worker paired to CID: {} for closure!", target);
        }

        void close_all()
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            log::trace(log_cat, "Closing {} workers!", num_workers);

            for (auto& [k, v] : workers)
            {
                if (workers[k].get())
                {
                    log::trace(log_cat, "Worker paired to CID: {} closing...", k);
                    v->close();

                    worker_sockets.erase(k);
                    log::debug(log_cat, "Worker paired to CID: {} closed!", k);
                }
            }

            workers.clear();
            worker_sockets.clear();
            num_workers = 0;

            log::debug(log_cat, "All workers closed!");
        }

        ~ZMQBridge()
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            close_all();

            if (active)
            {
                active = false;

                if (broker_thread.joinable())
                    broker_thread.join();
            }

            command.close();
            broker.close();

            ctx.shutdown();
            ctx.close();
            log::trace(log_cat, "ZMQBridge closed!");
        }

      private:
        bool active;

        ZMQBridge(Endpoint& e) : endpoint{e}
        {
            ctx = zmq::context_t();
            ctx.set(zmq::ctxopt::blocky, false);

            broker = zmq::socket_t(ctx, zmq::socket_type::router);
            broker.set(zmq::sockopt::linger, 0);
            command = zmq::socket_t(ctx, zmq::socket_type::router);
            command.set(zmq::sockopt::linger, 0);
        }

        void initialize()
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            std::promise<void> p;
            auto f = p.get_future();

            broker_thread = std::thread{&ZMQBridge::broker_loop, this, std::move(p)};

            log::trace(log_cat, "Waiting on broker thread...");
            f.get();
            log::trace(log_cat, "Broker thread active!");
        }

        void broker_loop(std::promise<void> p)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            try
            {
                log::trace(log_cat, "Binding broker socket...");
                broker.bind("inproc://broker");
                broker.set(zmq::sockopt::router_mandatory, true);

                broker_poll.socket = static_cast<void*>(broker);
                broker_poll.events = ZMQ_POLLIN;
                broker_poll.fd = 0;

                log::trace(log_cat, "Binding command socket...");
                command.bind("inproc://command");
                command.set(zmq::sockopt::router_mandatory, true);

                command_poll.socket = static_cast<void*>(command);
                command_poll.events = ZMQ_POLLIN;
                command_poll.fd = 0;

                /*
                    Initialize workers
                        - should some be initialized immediately and stand ready?
                */
            }
            catch (std::exception& e)
            {
                p.set_exception(std::current_exception());
                log::error(log_cat, "Exception caught in broker loop initialization: {}", e.what());
                return;
            }

            active = true;
            p.set_value();

            start_time = get_time();
            next_heartbeat = start_time + heartbeat;

            while (true)
            {
                if (active)
                {
                    // poll broker
                    // rv > 0 means events were detected; zmq_poll throws on error cases (rv < 0)
                    if (auto rv = zmq::poll(&broker_poll, 1, timeout); rv > 0)
                    {
                        if (auto r = zmq::recv_multipart(broker, std::back_inserter(frontend_buf.data)); r)
                        {
                            log::trace(log_cat, "Broker received {}-part message", *r);

                            // do something with it
                        }
                    }

                    // poll command
                    // rv > 0 means events were detected; zmq_poll throws on error cases (rv < 0)
                    if (auto rv = zmq::poll(&command_poll, 1, timeout); rv > 0)
                    {
                        if (auto r = zmq::recv_multipart(command, std::back_inserter(backend_buf.data)); r)
                        {
                            log::trace(log_cat, "Broker received {}-part message from worker", *r);

                            // do something with it

                            // clear it before moving to the next
                        }
                    }
                }
                else
                {
                    log::debug(log_cat, "ZMQBridge exiting broker loop...");
                    break;
                }

                /*
                    while true:
                        iterate through polls
                            clear expired workers

                        if incoming request:
                            dispatch input request to worker
                            continue

                        if incoming response:
                            relay response from worker to request originator
                            continue
                */
            }
        }

        // process incoming request
        void process_request()
        {
            //
        }

        // dispatches a request for a worker to handle
        void dispatch_request()
        {
            //
        }
    };
}  // namespace oxen::quic

/*
Maybe it makes sense to do it like this:

                        [                  libquic                   ]                  [     external destination    ]
                        [      ZMQBRIDGE    ][    quic::connection   ]


                                             [ worker ][ quic::stream ]                 [ quic::stream ][ ZMQ backend ]
                                             [ worker ][ quic::stream ]                 [ quic::stream ][ ZMQ backend ]
[ external source ]     [ inproc ][ command ][ worker ][ quic::stream ]                 [ quic::stream ][ ZMQ backend ]
                                             [ worker ][ quic::stream ]                 [ quic::stream ][ ZMQ backend ]
                                             [ worker ][ quic::stream ]                 [ quic::stream ][ ZMQ backend ]

    -> External source makes request to libquic inproc
    -> routed to correct worker via UUID (TBD) via command
    -> translate frame to bt
    -> sent through stream

    <- receives response from external destination
    <- translate frame to bt, insert some unique idendifier (TBD, maybe pubkey?)
    <- thread-safe return to inproc via command
    <- inproc returns to external source

*/
