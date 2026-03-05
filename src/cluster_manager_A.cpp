#include <silkit/SilKit.hpp>
#include <silkit/services/can/all.hpp>
#include <ecusim/CanTransport.hpp>
#include <oqs/oqs.h>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <random>
#include <algorithm>

using namespace SilKit;
using namespace SilKit::Services;
using namespace SilKit::Services::Can;

int main ()
{
    std::string participantName = "Cluster_A";
    std::string registryUri = "silkit://localhost:8500";
    std::string network = "CAN1";
    bool active = true;

    auto participant = SilKit::CreateParticipant(SilKit::Config::ParticipantConfigurationFromString(""), participantName, registryUri);
    auto* canCtrl = participant->CreateCanController("CANCtrl", network);

    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("ML-KEM-512");
    if (!kem) {
        std::cerr << "Error in KEM creation" << std::endl;
        return -1;
    }
    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS) {
        std::cerr << "Keypair generation error" << std::endl;
        OQS_KEM_free(kem);
        return -1;
    }

    std::vector<uint8_t> clusterKeyA(32);
    std::random_device rd;
    std::generate(clusterKeyA.begin(), clusterKeyA.end(), std::ref(rd));
    std::vector<uint8_t> key_acc(kem->length_shared_secret);
    std::vector<uint8_t> key_rpm(kem->length_shared_secret);
    std::vector<uint8_t> key_motor(kem->length_shared_secret);
    std::vector<uint8_t> key_c(kem->length_shared_secret);

    static bool pk_sent = false;
    bool clusterB = false;
    bool activeAcc = false;
    bool activeRpm = false;
    bool activeMotor = false;

    static CanReassembler reasCTC;
    static CanReassembler reasCTAcc;
    static CanReassembler reasCTRpm;
    static CanReassembler reasCTMotor;
    static CanReassembler reasRDSpd;
    static CanReassembler reasRDGear;
    static CanReassembler reasRDRpm;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId) {
         case 0x1a0:
            clusterB = true;
            break;
        case 0x200:
            activeAcc = true;
            break;
        case 0x300:
            activeRpm = true;
            break;
        case 0x500:
            activeMotor = true;
            break;
        case 0x1a2:
            if (reasCTC.OnFrame(event.frame)) {
                std::vector<uint8_t> ciphertext = reasCTC.buffer;
                if (OQS_KEM_decaps(kem, key_c.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS) {
                    std::cerr << "Error during decapsulation" << std::endl;
                    return;
                }
            }
            break;
        case 0x202:
            if (reasCTAcc.OnFrame(event.frame)) {
                std::vector<uint8_t> ciphertext = reasCTAcc.buffer;
                if (OQS_KEM_decaps(kem, key_acc.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS) {
                    std::cerr << "Error during decapsulation" << std::endl;
                    return;
                }
                SendOverCan(canCtrl, 0x025, encrypt_aes(clusterKeyA, key_acc));
            }
            break;
        case 0x302:
            if (reasCTRpm.OnFrame(event.frame)) {
                std::vector<uint8_t> ciphertext = reasCTRpm.buffer;
                if (OQS_KEM_decaps(kem, key_rpm.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS) {
                    std::cerr << "Error during decapsulation" << std::endl;
                    return;
                }
                SendOverCan(canCtrl, 0x035, encrypt_aes(clusterKeyA, key_rpm));
            }
            break;
        case 0x502:
            if (reasCTMotor.OnFrame(event.frame)) {
                std::vector<uint8_t> ciphertext = reasCTMotor.buffer;
                if (OQS_KEM_decaps(kem, key_motor.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS) {
                    std::cerr << "Error during decapsulation" << std::endl;
                    return;
                }
                SendOverCan(canCtrl, 0x055, encrypt_aes(clusterKeyA, key_motor));
            }
            break;
        case 0x4a4:
            if (reasRDSpd.OnFrame(event.frame)) {
                std::vector<uint8_t> redirect = decrypt_aes(reasRDSpd.buffer, key_c);
                redirect = encrypt_aes(redirect, clusterKeyA);
                SendOverCan(canCtrl, 0x404, redirect);
            }
            break;
        case 0x6a4:
            if (reasRDGear.OnFrame(event.frame)) {
                std::vector<uint8_t> redirect = decrypt_aes(reasRDGear.buffer, key_c);
                redirect = encrypt_aes(redirect, clusterKeyA);
                SendOverCan(canCtrl, 0x604, redirect);
            }
            break;
        case 0x304:
            if (reasRDRpm.OnFrame(event.frame)) {
                std::vector<uint8_t> redirect = decrypt_aes(reasRDRpm.buffer, clusterKeyA);
                redirect = encrypt_aes(redirect, key_c);
                SendOverCan(canCtrl, 0x3a4, redirect);
            }
            break;
        case 0x999:
            active = false;
            break;
        }
        if (!pk_sent && activeAcc && activeRpm && activeMotor && clusterB) {
            SendOverCan(canCtrl, 0x091, pk);
            pk_sent = true;
        }
    });

    canCtrl->Start();
    while(active) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    OQS_KEM_free(kem);
    return 0;
}

