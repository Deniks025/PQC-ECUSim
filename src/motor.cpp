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
    auto participant = SilKit::CreateParticipant(config, "ECU_MOTOR");
    auto* canCtrl = participant->CreateCanController("CAN_CTRL_MOTOR", "CAN1");
    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("Kyber512");
    static CanReassembler reassembler;
    std::vector<uint8_t> key(kem->length_shared_secret);
    std::vector<uint8_t> clusterKey(32);
    bool secureCluster = false;
    std::atomic<uint16_t> load{0};
    std::atomic<uint16_t> currentRpm{800};
    std::atomic<uint16_t> currentAcc{0};
    std::atomic<uint16_t> currentGear{1};
    const uint16_t max_rpm = 6000; // or "redline" rpm
    const float gearRatios[] = {0.0f, 3.50f, 2.10f, 1.45f, 1.00f, 0.80f};
    bool active = true;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId){
        case 0x091:
            if (reassembler.OnFrame(event.frame)){
                std::vector<uint8_t> pk = reassembler.buffer;
                if (!kem){
                    std::cerr << "Error in KEM creation" << std::endl;
                    return;
                }
                std::vector<uint8_t> ciphertext(kem->length_ciphertext);
                if (OQS_KEM_encaps(kem, ciphertext.data(), key.data(), pk.data()) != OQS_SUCCESS){
                    std::cerr << "Error during Encapsulation" << std::endl;
                    OQS_KEM_free(kem);
                    return;
                }
                SendOverCan(canCtrl, 0x502, ciphertext);
                OQS_KEM_free(kem);
            }
            break;
        case 0x055:
            if (reassembler.OnFrame(event.frame)){
                clusterKey = decrypt_aes(reassembler.buffer, key);
                secureCluster = true;
            }
            break;
        case 0x999:
            active = false;
            break;
        }
    });

    canCtrl->Start();
    SendOverCan(canCtrl, 0x500, {0x01});
    while(active){
        uint16_t acc = currentAcc.load();
        uint16_t rpm = currentRpm.load();
        uint16_t gear = currentGear.load();
        load.store(((acc*(1-(float)rpm/max_rpm))/gearRatios[gear])*10.0f);
        if(secureCluster){
            SendOverCan(canCtrl, 0x504, encrypt_aes(encode(load.load()), clusterKey));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

