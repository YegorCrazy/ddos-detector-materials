#include "DDoSDetector2.hpp"

#include "PacketParser.hpp"
#include "api/Packet.hpp"
#include "CommandLine.hpp"
#include "SwitchImpl.hpp"
#include "OFAgentImpl.hpp"
#include <chrono>
#include <runos/core/logging.hpp>
#include <fluid/of13msg.hh>

#include <chrono>
#include <string>
#include <cmath>
#include <boost/chrono.hpp>
#include <unordered_map>

namespace runos {

REGISTER_APPLICATION(DDoSDetector2, {"controller",
                                    "switch-manager",
                                    "topology",
                                    "of-server",
                                    "host-manager",
                                    ""})
                                
struct DDoSDetector2::FlowRemovedHandler final
    : OFMessageHandler<of13::FlowRemoved> {
        
    DDoSDetector2* app_;
    
    explicit FlowRemovedHandler(DDoSDetector2* app) : app_{app} {}
    
    bool process(of13::FlowRemoved& fr, OFConnectionPtr conn) override {
        auto dpid = fr.cookie() & DPID_MASK2;
        auto port_num = (fr.cookie() & PORT_NUMBER_MASK2) >> 16;
        app_->flows_removed[dpid][port_num] += 1;
        app_->packets_in_removed_flow_[fr.cookie()] = fr.packet_count();
        return false;
    }
};

const std::string DDoSDetector2::attackers_file_name_ = "attackers";

DDoSDetector2::~DDoSDetector2() {
    detection_thread_.interrupt();
}

void DDoSDetector2::CollectPortsInfo() {
    while (true)
    {
        std::vector<std::pair<uint64_t, uint64_t>> sus_ports;
        for (auto switch_ptr : switch_manager_->switches()) {
            auto dpid = switch_ptr->dpid();
            auto of_agent_future = of_server_->agent(dpid);
            of_agent_future.wait();
            auto of_agent = of_agent_future.get();
            
            for (const auto& port : switch_ptr->ports()) {
                auto port_num = port->number();
                if (port_num == 4294967294)
                    continue;
                auto response_future = of_agent->request_port_stats(port_num);
                response_future.wait();
                auto response = response_future.get();

                std::vector<double> features = {response.rx_packets(), response.tx_packets(),
                    (double)response.tx_packets() / response.rx_packets()};

                if (arima_prev_meanings_.find(dpid) == arima_prev_meanings_.end()
                    || arima_prev_meanings_[dpid].find(port_num) == arima_prev_meanings_[dpid].end())
                {
                    for (int i = 0; i < 3; ++i) {
                        for (int j = 0; j < arima_prev_features_num; ++j)
                        {
                            arima_prev_meanings_norm_[dpid][port_num][i][j] = 0;
                        }
                        arima_prev_meanings_[dpid][port_num][i] = 0;
                    }
                }

                bool is_sus = false;
                for (int i = 0; i < 3; ++i)
                {
                    auto new_meaning = features[i] - arima_prev_meanings_[dpid][port_num][i];
                    double predicted_meaning = 0;
                    for (int j = 0; j < ARIMA_PREV_FEATURES_NUM; ++j)
                    {
                        predicted_meaning += arima_prev_coefs_[i][j]
                            * arima_prev_meanings_norm_[dpid][port_num][i][j];
                    }
                    if (new_meaning > predicted_meaning + 10 && (new_meaning - predicted_meaning) > (0.15 * new_meaning))
                    {
                        //LOG(ERROR) << "port is sus: " << dpid << " " << port_num;
                        is_sus = true;
                    }
                    for (int j = 1; j < ARIMA_PREV_FEATURES_NUM; ++j)
                    {
                        arima_prev_meanings_norm_[dpid][port_num][i][j - 1] = arima_prev_meanings_norm_[dpid][port_num][i][j];
                    }
                    arima_prev_meanings_norm_[dpid][port_num][i][ARIMA_PREV_FEATURES_NUM - 1] = new_meaning;
                    arima_prev_meanings_[dpid][port_num][i] = features[i];
                    if (is_sus) break;
                }

                if (is_sus)
                {
                    sus_ports.push_back({dpid, port_num});
                }
            }
        }
        if (!sus_ports.empty())
        {
            CollectFlowsInfo(sus_ports);
        }
        boost::this_thread::sleep_for(boost::chrono::seconds(1));
    }
}

void DDoSDetector2::CollectFlowsInfo(const std::vector<std::pair<uint64_t, uint64_t>>& hosts) {
    std::vector<of13::FlowStats> flows;
    for (auto switch_ptr : switch_manager_->switches()) {
        auto dpid = switch_ptr->dpid();
        auto of_agent_future = of_server_->agent(dpid);
        of_agent_future.wait();
        auto of_agent = of_agent_future.get();

        ofp::flow_stats_request req;
        req.out_port = of13::OFPP_ANY;
        req.out_group = of13::OFPG_ANY;
        req.cookie_mask = 0;
        if (!of_agent)
            continue;
        auto response_future = of_agent->request_flow_stats(req);
        response_future.wait();
        auto response = response_future.get();

        for (const auto& flow_stat : response) {
            flows.push_back(flow_stat);
        }
    }
    std::unordered_multimap<uint64_t, of13::FlowStats> host_to_flow;
    for (auto& flow : flows) {
        uint32_t cookie = flow.cookie() & 0x00000000FFFFFFFFULL;
        host_to_flow.emplace(std::make_pair(cookie, flow));
    }
    for (const auto& [dpid, port] : hosts) {
        uint64_t cookie = (port << 16) | dpid;
        
        double FlowCount = host_to_flow.count(cookie);
        if (FlowCount == 0) {
            continue;
        }
        
        double SpeedOfFlowEntries = FlowCount + flows_removed[dpid][port];
        
        long long sum_packet_count = 0;
        std::unordered_map<uint64_t, long long> new_packets_in_flows;
        const auto range = host_to_flow.equal_range(cookie);
        for (auto it = range.first; it != range.second; ++it) {
            auto& flow_stat = (*it).second;
            auto cookie = flow_stat.cookie();
            sum_packet_count += flow_stat.packet_count();
            new_packets_in_flows[cookie] = flow_stat.packet_count();
        }
        int current_host_flows_removed = 0;
        std::vector<uint64_t> flows_to_remove;
        for (const auto& [flow_cookie, packets_num] : packets_in_removed_flow_) {
            if ((flow_cookie & (PORT_NUMBER_MASK2 | DPID_MASK2)) == cookie) {
                long long new_packets = packets_num;
                sum_packet_count += new_packets;
                new_packets_in_flows[flow_cookie] = new_packets;
                current_host_flows_removed += 1;
                flows_to_remove.push_back(flow_cookie);
            }
        }
        for (const auto& cookie : flows_to_remove) {
            packets_in_removed_flow_.erase(cookie);
        }
        long long flows_total = FlowCount + current_host_flows_removed;
        double AverageNumberOfFlowPackets = 0;
        if (flows_total != 0)
            AverageNumberOfFlowPackets = double(sum_packet_count) / flows_total;
        
        double VariationNumberOfFlowPackets = 0;
        if (flows_total != 0)
        {
            for (auto [_, packets_num] : new_packets_in_flows) {
                VariationNumberOfFlowPackets += std::pow(
                    packets_num - AverageNumberOfFlowPackets,
                    2);
            }
            VariationNumberOfFlowPackets = std::sqrt(VariationNumberOfFlowPackets / flows_total);
        }
        
        if (show_debug_)
            LOG(INFO) << "checking dpid " << dpid << " port " << port;

        bool is_malicious = CheckIfMalicious({FlowCount, SpeedOfFlowEntries, 
                                                AverageNumberOfFlowPackets,
                                                VariationNumberOfFlowPackets});
        
        if (is_malicious) {
            auto current_time = std::chrono::system_clock::now().time_since_epoch();
            auto current_seconds = std::chrono::duration_cast<std::chrono::seconds>(current_time).count();
            LOG(INFO) << "Host on dpid " << dpid << " port " << port << " may be malicious!";
            std::ofstream attackers(attackers_file_name_, std::ios::app);
            attackers << dpid << " " << port << " " << current_seconds << std::endl;
            attackers.close();
        }
        flows_removed[dpid][port] = 0;
    }
}

bool DDoSDetector2::CheckIfMalicious(std::array<double, features_num> features) {
    double res = 0;
    for (int i = 0; i < features_num; ++i) {
        res += (features[i] - mean_[i]) / scale_[i] * coefs_[i];
    }
    res += intercept_;
    if (show_debug_) {
        LOG(INFO) << "Got values: " << features[0] << " " << features[1] << " "
                   << features[2] << " " << features[3];
        LOG(INFO) << "Got result: " << res;
    }
    return res > 0;
}

void DDoSDetector2::init(Loader* loader, const Config& config) {
    switch_manager_ = SwitchManager::get(loader);
    of_server_ = OFServer::get(loader);
    host_manager_ = HostManager::get(loader);
    data_pickup_period_ = boost::chrono::seconds(config_get(
        config_cd(config, "ddos-detector"), "data-pickup-period", 3));
        
    CommandLine* cli = CommandLine::get(loader);
    cli->register_command(
        cli_pattern(R"(debug\s+on)"),
        [=](cli_match const& match) {
            this->show_debug_ = true;
        });
    cli->register_command(
        cli_pattern(R"(debug\s+off)"),
        [=](cli_match const& match) {
            this->show_debug_ = false;
        });
    
    std::string arima_weights_file_name = config_get(
        config_cd(config, "ddos-detector"), "arima_weights_file", "arima_weights");
    std::ifstream arima_weights_file(arima_weights_file_name);
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < arima_prev_features_num; ++j)
        {
            arima_weights_file >> arima_prev_coefs_[i][j];
            //std::cout << arima_prev_coefs_[i][j];
        }
    }
    arima_weights_file.close();
        
    std::string weights_file_name = config_get(
        config_cd(config, "ddos-detector"), "weights_file", "weights");
    std::ifstream weights_file(weights_file_name);
    for (int i = 0; i < features_num; ++i) {
        weights_file >> scale_[i];
    }
    for (int i = 0; i < features_num; ++i) {
        weights_file >> mean_[i];
    }
    for (int i = 0; i < features_num; ++i) {
        weights_file >> coefs_[i];
    }
    weights_file >> intercept_;
    weights_file.close();
    
    enabled_ = config_get(
        config_cd(config, "ddos-detector"), "enabled", true);
    
    handler_.reset(new FlowRemovedHandler(this));
    Controller::get(loader)->register_handler(handler_, -200);
}

void DDoSDetector2::startUp(class Loader*) {
    for (auto switch_ptr : switch_manager_->switches()) {
        auto dpid = switch_ptr->dpid();
        auto of_agent_future = of_server_->agent(dpid);
        of_agent_future.wait();
        auto of_agent = of_agent_future.get();
        for (const auto& port_ptr : (*switch_ptr).ports()) {
            // TODO make this just to ports connected to switches
            // TODO this relies on topology does not change
            unsigned port_num = (*port_ptr).number();
            flows_removed[dpid][port_num] = 0;
        }
    }
    if (enabled_) {
        detection_thread_ = boost::thread([&]() {
            this->CollectPortsInfo();
        });
    }
}

} // namespace runos
