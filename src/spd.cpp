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
    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("Kyber512");
    static CanReassembler reasPK;
    static CanReassembler reasKey;
    static CanReassembler reasRpm;
    static CanReassembler reasGear;
    std::vector<uint8_t> key(kem->length_shared_secret);
    std::vector<uint8_t> clusterKey(32);
    bool secureCluster = false;
    std::atomic<uint16_t> spd{0};
    std::atomic<uint16_t> currentRpm{0};
    std::atomic<uint16_t> currentGear{1};
    const float WheelCircumference = 1.98f;
    const float FinalDrive = 3.70f;
    const float gearRatios[] = {0.0f, 3.50f, 2.10f, 1.45f, 1.00f, 0.80f};
    bool active = true;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId){
            case 0x191:
                if (reasPK.OnFrame(event.frame)){
                    std::vector<uint8_t> pk = reasPK.buffer;
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
                    SendOverCan(canCtrl, 0x412, ciphertext);
                }
                break;
            case 0x145:
                if (reasKey.OnFrame(event.frame)){
                    clusterKey = decrypt_aes(reasKey.buffer, key);
                    secureCluster = true;
                }
                break;
            case 0x314:
                if (reasRpm.OnFrame(event.frame)){
                    currentRpm.store(decode(decrypt_aes(reasRpm.buffer, clusterKey)));
                }
                break;
            case 0x614:
                if (reasGear.OnFrame(event.frame)){
                    currentGear.store(decode(decrypt_aes(reasGear.buffer, clusterKey)));
                }
                break;
            case 0x999:
                active = false;
                break;
        }
    });
    canCtrl->Start();
    SendOverCan(canCtrl, 0x410, {0x01});
    while(active){
        uint16_t rpm = currentRpm.load();
        uint16_t gear = currentGear.load();
        float targetSpeed = (((float)rpm * WheelCircumference * 60.0f) / (gearRatios[gear] * FinalDrive * 1000.0f) * 10.0f);
        float currentSpeed = spd.load();
        float smoothSpeed = currentSpeed + 0.1f * (targetSpeed - currentSpeed);
        spd.store(smoothSpeed);
        if(secureCluster){
            SendOverCan(canCtrl, 0x414, encrypt_aes(encode(spd.load()), clusterKey));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    OQS_KEM_free(kem);
}

