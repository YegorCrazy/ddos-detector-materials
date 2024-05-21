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

class DatasetCollector2 : public Application
{
    Q_OBJECT
    SIMPLE_APPLICATION(DatasetCollector2, "dataset-collector-2")
public:
    void init(Loader* loader, const Config& config) override;
    void CollectFlowsInfo(int iter_num, std::ofstream& file);
    ~DatasetCollector2();

private:
    SwitchManager* switch_manager_;
    OFServer* of_server_;
	
    boost::chrono::seconds data_pickup_period_;

};

} // namespace runos
