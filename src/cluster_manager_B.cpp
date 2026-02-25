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

int main (){
    std::string participantName = "Cluster_B";
    std::string registryUri = "silkit://localhost:8500";
    std::string network = "CAN1";
    bool active = true;

    auto participant = SilKit::CreateParticipant(SilKit::Config::ParticipantConfigurationFromString(""), participantName, registryUri);
    auto* canCtrl = participant->CreateCanController("CANCtrl", network);

    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("Kyber512");
    if (!kem){
        std::cerr << "Error in KEM creation" << std::endl;
        return -1;
    }
    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS){
        std::cerr << "Keypair generation error" << std::endl;
        OQS_KEM_free(kem);
        return -1;
    }
    std::vector<uint8_t> clusterKeyB(32);
    std::random_device rd;
    std::generate(clusterKeyB.begin(), clusterKeyB.end(), std::ref(rd));
    std::vector<uint8_t> key_spd(kem->length_shared_secret);
    std::vector<uint8_t> key_trm(kem->length_shared_secret);
    std::vector<uint8_t> key_c(kem->length_shared_secret);
    static bool pk_sent = false;
    bool secureSpd = false;
    bool secureTrm = false;
    bool activeSpd = false;
    bool activeTrm = false;
    static CanReassembler reasPK;
    static CanReassembler reasCTSpd;
    static CanReassembler reasCTGear;
    static CanReassembler reasRDRpm;
    static CanReassembler reasRDSpd;
    static CanReassembler reasRDGear;



    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId) {
        case 0x091:
            if (reasPK.OnFrame(event.frame)){
                std::vector<uint8_t> pka = reasPK.buffer;
                if (!kem){
                    std::cerr << "Error in KEM creation" << std::endl;
                    return;
                }
                std::vector<uint8_t> ciphertext(kem->length_ciphertext);
                if (OQS_KEM_encaps(kem, ciphertext.data(), key_c.data(), pka.data()) != OQS_SUCCESS){
                    std::cerr << "Error during Encapsulation" << std::endl;
                    OQS_KEM_free(kem);
                    return;
                }
                SendOverCan(canCtrl, 0x1a2, ciphertext);
            }
            break;
        case 0x410:
            activeSpd = true;
            break;
        case 0x610:
            activeTrm = true;
            break;
        case 0x412:
            if (reasCTSpd.OnFrame(event.frame)){
                std::vector<uint8_t> ciphertext = reasCTSpd.buffer;
                if (OQS_KEM_decaps(kem, key_spd.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS){
                    std::cerr << "Error during decapsulation" << std::endl;
                    return;
                }
                SendOverCan(canCtrl, 0x145, encrypt_aes(clusterKeyB, key_spd));
            }
            break;
        case 0x612:
            if (reasCTGear.OnFrame(event.frame)){
                std::vector<uint8_t> ciphertext = reasCTGear.buffer;
                if (OQS_KEM_decaps(kem, key_trm.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS){
                    std::cerr << "Error during decapsulation" << std::endl;
                    return;
                }
                SendOverCan(canCtrl, 0x165, encrypt_aes(clusterKeyB, key_trm));
            }
            break;
        case 0x3a4:
            if (reasRDRpm.OnFrame(event.frame)){
                std::vector<uint8_t> redirect = decrypt_aes(reasRDRpm.buffer, key_c);
                redirect = encrypt_aes(redirect, clusterKeyB);
                SendOverCan(canCtrl, 0x314, redirect);
            }
            break;
        case 0x414:
            if (reasRDSpd.OnFrame(event.frame)){
                std::vector<uint8_t> redirect = decrypt_aes(reasRDSpd.buffer, clusterKeyB);
                redirect = encrypt_aes(redirect, key_c);
                SendOverCan(canCtrl, 0x4a4, redirect);
            }
            break;
        case 0x614:
            if (reasRDGear.OnFrame(event.frame)){
                std::vector<uint8_t> redirect = decrypt_aes(reasRDGear.buffer, clusterKeyB);
                redirect = encrypt_aes(redirect, key_c);
                SendOverCan(canCtrl, 0x6a4, redirect);
            }
            break;
        case 0x999:
            active = false;
            break;
        }
        if (!pk_sent && activeSpd && activeTrm) {
            SendOverCan(canCtrl, 0x191, pk);
            pk_sent = true;
        }
    });

    canCtrl->Start();
    SendOverCan(canCtrl, 0x1a0, {0x01});
    while(active){
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    OQS_KEM_free(kem);
    return 0;
}

