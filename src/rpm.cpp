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
    auto participant = SilKit::CreateParticipant(config, "ECU_RPM");
    auto* canCtrl = participant->CreateCanController("CAN_CTRL_RPM", "CAN1");
    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("Kyber512");
    static CanReassembler reassembler;
    std::vector<uint8_t> key(kem->length_shared_secret);
    std::vector<uint8_t> clusterKey(32);
    bool secureCluster = false;
    std::atomic<uint16_t> rpm{800};
    std::atomic<uint16_t> currentAcc{0};
    std::atomic<uint16_t> currentGear{1};
    const uint16_t idle_rpm = 800;
    const uint16_t max_rpm = 6000; // or "redline" rpm
    bool active = true;
    uint16_t lastGear = 1;

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
                SendOverCan(canCtrl, 0x302, ciphertext);
                OQS_KEM_free(kem);
            }
            break;
        case 0x035:
            if (reassembler.OnFrame(event.frame)){
                clusterKey = decrypt_aes(reassembler.buffer, key);
                secureCluster = true;
            }
            break;
        case 0x204:
            if (reassembler.OnFrame(event.frame)){
                currentAcc.store(decode(decrypt_aes(reassembler.buffer, clusterKey)));
            }
            break;
        case 0x604:
            if (reassembler.OnFrame(event.frame)){
                currentGear.store(decode(decrypt_aes(reassembler.buffer, clusterKey)));
            }
            break;
        case 0x999:
            active = false;
            break;
        }
    });

    canCtrl->Start();
    SendOverCan(canCtrl, 0x300, {0x01});
    while(active){
        uint16_t acc = currentAcc.load();
        uint16_t tempRpm = rpm.load();
        uint16_t gear = currentGear.load();

        if (gear > lastGear) {
            if (tempRpm > 2000 + idle_rpm) {
                tempRpm -= 2000;
            } else {
                tempRpm = idle_rpm;
            }
            lastGear = gear;
        }
        else if (gear < lastGear) {
            if (tempRpm + 2000 < max_rpm) {
                tempRpm += 2000;
            } else {
                tempRpm = max_rpm;
            }
            lastGear = gear;
        }

        if (acc > 0) {
            uint16_t gain = acc;
            if (tempRpm + gain < max_rpm) {
                tempRpm += gain;
            } else {
                tempRpm = max_rpm;
            }
        }
        else {
            uint16_t decay = 75;
            if (tempRpm > idle_rpm + decay) {
                tempRpm -= decay;
            } else {
                tempRpm = idle_rpm;
            }
        }
        rpm.store(tempRpm);
        if(secureCluster){
            SendOverCan(canCtrl, 0x304, encrypt_aes(encode(tempRpm), clusterKey));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}
