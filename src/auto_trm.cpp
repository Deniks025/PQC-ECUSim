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
    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("Kyber512");
    static CanReassembler reassembler;
    std::vector<uint8_t> key(kem->length_shared_secret);
    std::vector<uint8_t> clusterKey(32);
    bool secureCluster = false;
    std::atomic<uint16_t> gear{1};
    std::atomic<uint16_t> currentRpm{0};
    bool active = true;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId){
        case 0x191:
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
                SendOverCan(canCtrl, 0x612, ciphertext);
                OQS_KEM_free(kem);
            }
            break;
        case 0x165:
            if (reassembler.OnFrame(event.frame)){
                clusterKey = decrypt_aes(reassembler.buffer, key);
                secureCluster = true;
            }
            break;
        case 0x314:
            if (reassembler.OnFrame(event.frame)){
                currentRpm.store(decode(decrypt_aes(reassembler.buffer, clusterKey)));
            }
            break;
        case 0x999:
            active = false;
            break;
        }
    });
    canCtrl->Start();
    SendOverCan(canCtrl, 0x610, {0x01});
    while(active){
        uint16_t rpm = currentRpm.load();
        if (gear.load() <= 4 && rpm >= 3600){
            gear.store(gear.load()+1);
        } else if(gear.load() > 1 && rpm <= 1200){
            gear.store(gear.load()-1);
        }
        if(secureCluster){
            SendOverCan(canCtrl, 0x614, encrypt_aes(encode(gear.load()), clusterKey));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

