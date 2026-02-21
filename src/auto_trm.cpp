#include <silkit/SilKit.hpp>
#include <silkit/services/can/all.hpp>
#include <oqs/oqs.h>
#include <ecusim/CanTransport.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>
#include <vector>

using namespace SilKit;
using namespace SilKit::Services::Can;

int main()
{
    auto config = SilKit::Config::ParticipantConfigurationFromFile("silkit_config.yaml");
    auto participant = SilKit::CreateParticipant(config, "ECU_TRM");
    auto* canCtrl = participant->CreateCanController("CAN_CTRL_TRM", "CAN1");

    static CanReassembler reassembler;

    std::atomic<uint16_t> gear{1};
    std::atomic<uint16_t> currentRpm{0};
    bool active = true;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        if (event.frame.canId == 0x300){
            if (reassembler.OnFrame(event.frame)){
                currentRpm.store(decode(reassembler.buffer));
            }
        }
        if (event.frame.canId == 0x999){
            active = false;
        }
    });
    canCtrl->Start();
    while(active){
        uint16_t rpm = currentRpm.load();
        if (gear.load() <= 4 && rpm >= 3600){
            gear.store(gear.load()+1);
        } else if(gear.load() > 1 && rpm <= 1200){
            gear.store(gear.load()-1);
        }
        SendOverCan(canCtrl, 0x600, encode(gear.load()));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

