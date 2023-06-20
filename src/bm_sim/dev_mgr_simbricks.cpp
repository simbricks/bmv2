/*
 * Copyright 2023 Max Planck Institute for Software Systems, and
 * National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <signal.h>
#include <utility>
#include <unordered_map>
#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/logger.h>

namespace bm
{
    class NetPort
    {
    public:
        enum RxPollState
        {
            kRxPollSuccess = 0,
            kRxPollFail = 1,
            kRxPollSync = 2,
        };

        NetPort(const std::string &path, const struct SimbricksBaseIfParams &params, bool sync)
            : path_(path),
              sync_(sync),
              rx_(nullptr),
              params_(params)
        {
            memset(&netif_, 0, sizeof(netif_));
            params_.sync_mode = sync ? kSimbricksBaseIfSyncOptional : kSimbricksBaseIfSyncDisabled;
            params_.sock_path = path.c_str();
            params_.blocking_conn = false;
        }

        NetPort(const NetPort &other)
            : netif_(other.netif_),
              path_(other.path_),
              sync_(other.sync_),
              rx_(other.rx_),
              params_(other.params_)
        {
        }

        bool prepare()
        {
            if (SimbricksBaseIfInit(&netif_.base, &params_))
            {
                Logger::get()->error("prepare: SimbricksBaseIfInit failed");
                return false;
            }
            if (SimbricksBaseIfConnect(&netif_.base))
            {
                Logger::get()->error("prepare: SimbricksBaseIfConnect failed");
                return false;
            }
            return true;
        }

        bool is_sync()
        {
            return sync_;
        }

        void sync(uint64_t cur_ts)
        {
            while (SimbricksNetIfOutSync(&netif_, cur_ts))
            {
            }
        }

        uint64_t next_timestamp()
        {
            return SimbricksNetIfInTimestamp(&netif_);
        }

        enum RxPollState rx_packet(const void *&data, size_t &len, uint64_t cur_ts)
        {
            assert(rx_ == nullptr);

            rx_ = SimbricksNetIfInPoll(&netif_, cur_ts);
            if (!rx_)
                return kRxPollFail;

            uint8_t type = SimbricksNetIfInType(&netif_, rx_);
            if (type == SIMBRICKS_PROTO_NET_MSG_PACKET)
            {
                data = (const void *)rx_->packet.data;
                len = rx_->packet.len;
                return kRxPollSuccess;
            }
            else if (type == SIMBRICKS_PROTO_MSG_TYPE_SYNC)
            {
                return kRxPollSync;
            }
            else
            {
                Logger::get()->error("rx_packet: unsupported type");
                abort();
            }
        }

        void rx_done()
        {
            assert(rx_ != nullptr);

            SimbricksNetIfInDone(&netif_, rx_);
            rx_ = nullptr;
        }

        bool tx_packet(const void *data, size_t len, uint64_t cur_ts)
        {
            volatile union SimbricksProtoNetMsg *msg_to =
                SimbricksNetIfOutAlloc(&netif_, cur_ts);
            if (!msg_to && !sync_)
            {
                return false;
            }
            else if (!msg_to && sync_)
            {
                while (!msg_to)
                    msg_to = SimbricksNetIfOutAlloc(&netif_, cur_ts);
            }
            volatile struct SimbricksProtoNetMsgPacket *rx;
            rx = &msg_to->packet;
            rx->len = len;
            rx->port = 0;
            memcpy((void *)rx->data, data, len);

            SimbricksNetIfOutSend(&netif_, msg_to, SIMBRICKS_PROTO_NET_MSG_PACKET);
            return true;
        }

    public:
        struct SimbricksNetIf netif_;

    protected:
        const std::string path_;
        bool sync_;
        volatile union SimbricksProtoNetMsg *rx_;

    private:
        struct SimbricksBaseIfParams params_;
    };

    static int exiting = 0;

    static void sigint_handler(int dummy)
    {
        exiting = 1;
    }

    class SimbricksDevMgr : public DevMgrIface
    {
    public:
        SimbricksDevMgr(device_id_t device_id,
                        const struct SimbricksBaseIfParams &params,
                        bool sync,
                        std::shared_ptr<TransportIface> notifications_transport)
            : params_(params),
              sync_(sync),
              cur_ts_(0)
        {
            p_monitor = PortMonitorIface::make_active(device_id, notifications_transport);
        }

    private:
        ~SimbricksDevMgr() override
        {
            pthread_join(adaptor_thread_, nullptr);
        }

        ReturnCode port_add_(const std::string &iface_name, port_t port_num, const PortExtras &port_extras) override
        {
            std::pair<port_t, NetPort> port(port_num, NetPort(iface_name, params_, sync_));
            ports.insert(port);

            PortInfo p_info(port_num, iface_name, port_extras);

            Lock lock(mutex_);
            port_info_.emplace(port_num, std::move(p_info));

            return ReturnCode::SUCCESS;
        }

        ReturnCode port_remove_(port_t port_num) override
        {
            ports.erase(port_num);

            Lock lock(mutex_);
            port_info_.erase(port_num);

            return ReturnCode::SUCCESS;
        }

        void transmit_fn_(port_t port_num, const char *buffer, int len) override
        {
            auto p = ports.find(port_num);
            if (p == ports.end())
            {
                Logger::get()->error("transmit_fn_: port not added");
                abort();
            }
            auto &port = p->second;
            port.tx_packet(buffer, len, cur_ts_);
        }

        void start_() override
        {
            size_t n = ports.size();
            struct SimBricksBaseIfEstablishData ests[n];
            struct SimbricksProtoNetIntro intro;

            Logger::get()->info("start connecting...");
            for (size_t i = 0; i < n; i++)
            {
                NetPort &p = ports.at(i);
                ests[i].base_if = &p.netif_.base;
                ests[i].tx_intro = &intro;
                ests[i].tx_intro_len = sizeof(intro);
                ests[i].rx_intro = &intro;
                ests[i].rx_intro_len = sizeof(intro);

                if (!p.prepare())
                {
                    Logger::get()->error("start_: failed to prepare port");
                    abort();
                }
            }

            if (SimBricksBaseIfEstablish(ests, n))
            {
                Logger::get()->error("start_: fail to establish interface");
                abort();
            }
            Logger::get()->info("done connecting");

            signal(SIGINT, sigint_handler);
            signal(SIGTERM, sigint_handler);

            if (pthread_create(&adaptor_thread_, nullptr, run_adaptor_, this))
            {
                Logger::get()->error("start_: fail to start adaptor thread");
                abort();
            }
        }

        ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie) override
        {
            pkt_handler = handler;
            pkt_cookie = cookie;
            return ReturnCode::SUCCESS;
        }

        bool port_is_up_(port_t port) const override
        {
            // After setup, port is always up
            return port_info_.count(port);
        }

        std::map<port_t, PortInfo> get_port_info_() const override
        {
            std::map<port_t, PortInfo> info;
            {
                Lock lock(mutex_);
                info = port_info_;
            }
            for (auto &pi : info)
            {
                pi.second.is_up = port_is_up_(pi.first);
            }
            return info;
        }

        PortStats get_port_stats_(port_t port) const override
        {
            // TODO: return proper port stats
            return {0, 0, 0, 0};
        }

        PortStats clear_port_stats_(port_t port) override
        {
            // TODO: clear port stats
            return {0, 0, 0, 0};
        }

        static void *run_adaptor_(void *data)
        {
            assert(data != nullptr);
            SimbricksDevMgr *dev = (SimbricksDevMgr *)data;
            uint64_t cur_ts = 0;

            Logger::get()->info("Adaptor start polling");
            while (!exiting)
            {
                for (auto &p : dev->ports)
                {
                    auto &port = p.second;
                    port.sync(cur_ts);
                }

                uint64_t min_ts;
                do
                {
                    min_ts = ULLONG_MAX;
                    for (auto &p : dev->ports)
                    {
                        auto &port_num = p.first;
                        auto &port = p.second;
                        const void *pkt_data;
                        size_t pkt_len;

                        enum NetPort::RxPollState poll = port.rx_packet(pkt_data, pkt_len, cur_ts);
                        if (poll == NetPort::kRxPollFail)
                        {
                            continue;
                        }
                        else if (poll == NetPort::kRxPollSuccess)
                        {
                            using function_t = void(int, const void *, int, void *);
                            function_t *const *ptr_fun = dev->pkt_handler.target<function_t *>();
                            (*ptr_fun)(port_num, pkt_data, pkt_len, dev->pkt_cookie);
                        }
                        else if (poll == NetPort::kRxPollSync)
                        {
                            // TODO
                        }
                        else
                        {
                            Logger::get()->error("Unsupported poll result");
                            abort();
                        }
                        port.rx_done();
                        if (port.is_sync())
                        {
                            uint64_t ts = port.next_timestamp();
                            min_ts = ts < min_ts ? ts : min_ts;
                        }
                    }
                } while (!exiting && (min_ts <= cur_ts));

                if (min_ts < ULLONG_MAX)
                {
                    cur_ts = min_ts;
                }
            }

            return nullptr;
        }

    private:
        using Mutex = std::mutex;
        using Lock = std::lock_guard<std::mutex>;

        mutable Mutex mutex_;
        std::map<port_t, DevMgrIface::PortInfo> port_info_;
        struct SimbricksBaseIfParams params_;
        bool sync_;
        uint64_t cur_ts_;
        pthread_t adaptor_thread_;

    public:
        std::unordered_map<port_t, NetPort> ports;
        PacketHandler pkt_handler;
        void *pkt_cookie;
    };

    void DevMgr::set_dev_mgr_simbricks(device_id_t device_id,
                                       const struct SimbricksBaseIfParams &params,
                                       bool sync,
                                       std::shared_ptr<TransportIface> notifications_transport)
    {
        assert(!pimp);
        pimp = std::unique_ptr<DevMgrIface>(
            new SimbricksDevMgr(device_id, params, sync, notifications_transport));
    }

} // namespace bm
