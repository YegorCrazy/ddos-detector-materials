#pragma once

#include "Application.hpp"
#include "Config.hpp"
#include "Loader.hpp"
#include "SwitchManager.hpp"
#include "OFServer.hpp"
#include "api/SwitchFwd.hpp"
#include "oxm/openflow_basic.hh"

#include <fstream>
#include <unordered_map>

namespace runos {

using SwitchPtr = safe::shared_ptr<Switch>;
namespace of13 = fluid_msg::of13;

class DatasetCollector : public Application
{
    Q_OBJECT
    SIMPLE_APPLICATION(DatasetCollector, "dataset-collector")
public:
    void init(Loader* loader, const Config& config) override;
    void CollectFlowsInfo(int iter_num, std::ofstream& file, int label);
    ~DatasetCollector();

private:
    struct FlowRemovedHandler;
    std::shared_ptr<FlowRemovedHandler> handler_;
    SwitchManager* switch_manager_;
    OFServer* of_server_;
	
    boost::chrono::seconds data_pickup_period_;
    
    std::unordered_map<uint64_t, long long> packets_in_removed_flow_;
    long long flows_removed = 0;
};

} // namespace runos
