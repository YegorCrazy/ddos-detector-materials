#pragma once

#include "Application.hpp"
#include "Config.hpp"
#include "Loader.hpp"
#include "SwitchManager.hpp"
#include "OFServer.hpp"
#include "api/SwitchFwd.hpp"
#include "oxm/openflow_basic.hh"

#include "../../host-manager/include/HostManager.hpp"

#include <fstream>
#include <unordered_map>
#include <array>
#include <atomic>

#include <boost/thread/thread.hpp>

namespace runos {

using SwitchPtr = safe::shared_ptr<Switch>;
namespace of13 = fluid_msg::of13;

namespace {

const inline int FEATURES_NUM2 = 4;
const inline unsigned long long PORT_NUMBER_MASK2 = 0x00000000FFFF0000ULL;
const inline unsigned long long DPID_MASK2 = 0x000000000000FFFFULL;

const inline unsigned ARIMA_PREV_FEATURES_NUM = 2;

using arima_set = std::array<std::array<double, ARIMA_PREV_FEATURES_NUM>, 3>;

}

class DDoSDetector2 : public Application
{
    Q_OBJECT
    SIMPLE_APPLICATION(DDoSDetector2, "ddos-detector2")
public:
    void init(Loader* loader, const Config& config) override;
    void startUp(class Loader*) override;
    bool CheckIfMalicious(std::array<double, FEATURES_NUM2> features);
    void CollectFlowsInfo(const std::vector<std::pair<uint64_t, uint64_t>>& hosts);
    void CollectPortsInfo();
    ~DDoSDetector2();

private:
    static const inline int features_num = FEATURES_NUM2;
    static const inline int arima_prev_features_num = ARIMA_PREV_FEATURES_NUM;
    struct FlowRemovedHandler;
    std::shared_ptr<FlowRemovedHandler> handler_;
    SwitchManager* switch_manager_;
    OFServer* of_server_;
    HostManager* host_manager_;
	
    boost::chrono::seconds data_pickup_period_;
    boost::thread detection_thread_;
    
    std::array<double, FEATURES_NUM2> scale_;
    std::array<double, FEATURES_NUM2> mean_;
    std::array<double, FEATURES_NUM2> coefs_;
    double intercept_;

    arima_set arima_prev_coefs_;
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, arima_set>> arima_prev_meanings_norm_;
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::array<double, 3>>> arima_prev_meanings_;
    
    std::unordered_map<uint64_t, std::atomic_llong> packets_in_removed_flow_; // flow cookie to packets number
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::atomic_llong>> flows_removed; // dpid and port number to removed flows num
    
    bool show_debug_ = false;
    bool enabled_;

    static const std::string attackers_file_name_;
};

} // namespace runos
