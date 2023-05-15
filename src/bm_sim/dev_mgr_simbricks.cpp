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

#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/logger.h>

extern "C"
{
#include <simbricks/network/if.h>
}

namespace bm
{
    class SimbricksDevMgr : public DevMgrIface
    {
    public:
        SimbricksDevMgr(device_id_t device_id,
                        struct SimbricksBaseIfParams params,
                        std::shared_ptr<TransportIface> notifications_transport)
        {
            p_monitor = PortMonitorIface::make_active(device_id, notifications_transport);

            params.blocking_conn = false;

            if (SimbricksBaseIfInit(&netif.base, &params))
            {
                Logger::get()->error("Init: SimbricksBaseIfInit failed");
                abort();
            }
        }

    private:
        ~SimbricksDevMgr() override
        {
        }

        ReturnCode port_add_(const std::string &iface_name, port_t port_num, const PortExtras &port_extras) override
        {
            // TODO: SimBricks port add

            PortInfo p_info(port_num, iface_name, port_extras);

            Lock lock(mutex);
            port_info.emplace(port_num, std::move(p_info));

            return ReturnCode::SUCCESS;
        }

        ReturnCode port_remove_(port_t port_num) override
        {
            // TODO: SimBricks port remove

            Lock lock(mutex);
            port_info.erase(port_num);

            return ReturnCode::SUCCESS;
        }

        void transmit_fn_(port_t port_num, const char *buffer, int len) override
        {
            // TODO: SimBricks packet tx
        }

        void start_() override
        {
            // TODO: SimBricks start
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
            return port_info.count(port);
        }

        std::map<port_t, PortInfo> get_port_info_() const override
        {
            std::map<port_t, PortInfo> info;
            {
                Lock lock(mutex);
                info = port_info;
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

    private:
        using Mutex = std::mutex;
        using Lock = std::lock_guard<std::mutex>;

        mutable Mutex mutex;
        struct SimbricksNetIf netif;
        std::map<port_t, DevMgrIface::PortInfo> port_info;
        PacketHandler pkt_handler;
        void *pkt_cookie;
    };

    void DevMgr::set_dev_mgr_simbricks(device_id_t device_id,
                                       struct SimbricksBaseIfParams params,
                                       std::shared_ptr<TransportIface> notifications_transport)
    {
        assert(!pimp);
        pimp = std::unique_ptr<DevMgrIface>(
            new SimbricksDevMgr(device_id, params, notifications_transport));
    }

} // namespace bm
