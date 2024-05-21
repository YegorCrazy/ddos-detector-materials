#include "DatasetCollector2.hpp"

#include "PacketParser.hpp"
#include "api/Packet.hpp"
#include "CommandLine.hpp"
#include "SwitchImpl.hpp"
#include "OFAgentImpl.hpp"
#include <runos/core/logging.hpp>
#include <fluid/of13msg.hh>

#include <string>
#include <boost/chrono.hpp>

namespace runos {

REGISTER_APPLICATION(DatasetCollector2, {"controller",
                                "switch-manager",
                                "topology",
                                "of-server",
                                "command-line",
                                ""})

DatasetCollector2::~DatasetCollector2() = default;
                                
void DatasetCollector2::init(Loader* loader, const Config& config) {
    switch_manager_ = SwitchManager::get(loader);
    of_server_ = OFServer::get(loader);
    CommandLine* cli = CommandLine::get(loader);
    
    // registering command: collect dataset n filename.csv label
    // adding n rows to file "filename.csv"
    cli->register_command(
        cli_pattern(R"(collect\s+dataset2\s+([0-9]+)\s+(.+\.csv))"),
        [=](cli_match const& match) {
            std::ofstream file;
            file.open(match[2], std::ios::app);
            this->CollectFlowsInfo(std::stoi(match[1]), file);
            file.close();
        });
    data_pickup_period_ = boost::chrono::seconds(config_get(
        config_cd(config, "dataset-collector-2"), "data-pickup-period", 3));
}

void DatasetCollector2::CollectFlowsInfo(int iter_num, std::ofstream& file) {
    for (int i = 0; i < iter_num; ++i) {
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

                LOG(INFO) << dpid << "," << port_num << ","
                    << response.rx_packets() << "," << response.tx_packets() << ","
                    << std::endl;
                
                if (dpid == 1 && port_num == 1)
                    file << response.rx_packets() << "," << response.tx_packets() << std::endl;
            }
        }

        LOG(INFO) << std::endl;
        boost::this_thread::sleep_for(data_pickup_period_);
    }
    LOG(INFO) << "all info substracted";
}

} // namespace runos
