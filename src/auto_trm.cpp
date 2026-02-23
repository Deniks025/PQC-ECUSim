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
    uint8_t key[32] = {0x69, 0xd3, 0x68, 0x1a, 0x72, 0x28, 0x2e, 0x24,
        0x42, 0xb2, 0x6a, 0xfa, 0xed, 0x94, 0x48, 0xbe,
        0x3c, 0x64, 0x56, 0xdf, 0xa1, 0x32, 0xf8, 0x6d,
        0x4f, 0x96, 0x9a, 0xfa, 0xfc, 0xad, 0x35, 0x5c};

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        if (event.frame.canId == 0x300){
            if (reassembler.OnFrame(event.frame)){
                currentRpm.store(decode(decrypt_aes(reassembler.buffer, key)));
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
        SendOverCan(canCtrl, 0x600, encrypt_aes(encode(gear.load()), key));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

