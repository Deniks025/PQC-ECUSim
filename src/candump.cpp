#include <silkit/SilKit.hpp>
#include <silkit/services/can/all.hpp>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <thread>

using namespace SilKit;
using namespace SilKit::Services;
using namespace SilKit::Services::Can;

int main (){
    std::string participantName = "CAN_DUMP";
    std::string registryUri = "silkit://localhost:8500";
    std::string network = "CAN1";
    bool active = true;

    auto participant = SilKit::CreateParticipant(SilKit::Config::ParticipantConfigurationFromString(""), participantName, registryUri);
    auto* canController = participant->CreateCanController("CANCtrl", network);

    std::ofstream logfile("can_log.txt");

    canController->AddFrameHandler(
        [&](ICanController*, const CanFrameEvent& event)
        {
            const auto& frame = event.frame;
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            std::stringstream ss;

            ss << "[" << now << "] "
            << "ID:0x" << std::hex << frame.canId
            << " DLC:" <<std::dec << (int)frame.dlc
            << " DATA:";

            for(int i = 0; i < frame.dlc; i++){
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)frame.dataField[i] << " ";
            }
            std::string line = ss.str();
            std::cout << line << std::endl;
            logfile << line << std::endl;

            if (event.frame.canId == 0x999){
                active = false;
            }
        });

    canController->Start();
    std::cout << "CAN FRAMES ON NETWORK: " << network<< std::endl;

    while(active){
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    logfile.close();
    return 0;
}
