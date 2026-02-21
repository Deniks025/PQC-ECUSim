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
    auto participant = SilKit::CreateParticipant(config, "ECU_SPD");
    auto* canCtrl = participant->CreateCanController("CAN_CTRL_SPD", "CAN1");

    static CanReassembler reassembler;

    std::atomic<uint16_t> spd{0};
    std::atomic<uint16_t> currentRpm{0};
    std::atomic<uint16_t> currentGear{1};
    const float WheelCircumference = 1.98f;
    const float FinalDrive = 3.70f;
    const float gearRatios[] = {0.0f, 3.50f, 2.10f, 1.45f, 1.00f, 0.80f};
    bool active = true;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        if (event.frame.canId == 0x300){
            if (reassembler.OnFrame(event.frame)){
                currentRpm.store(decode(reassembler.buffer));
            }
        }
        if (event.frame.canId == 0x600){
            if (reassembler.OnFrame(event.frame)){
                currentGear.store(decode(reassembler.buffer));
            }
        }
        if (event.frame.canId == 0x999){
            active = false;
        }
    });
    canCtrl->Start();
    while(active){
        uint16_t rpm = currentRpm.load();
        uint16_t gear = currentGear.load();
        spd.store((((float)rpm * WheelCircumference * 60.0f) / (gearRatios[gear] * FinalDrive * 1000.0f)*10.0f));
        SendOverCan(canCtrl, 0x400, encode(spd.load()));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

