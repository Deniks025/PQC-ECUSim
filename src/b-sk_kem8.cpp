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

std::atomic<bool> done{false};

using namespace SilKit;
using namespace SilKit::Services::Can;

int main()
{
    auto config = SilKit::Config::ParticipantConfigurationFromFile("silkit_config.yaml");
    auto participant = SilKit::CreateParticipant(config, "ECU_B");
    auto* canCtrl = participant->CreateCanController("CAN_CTRL_B", "CAN1");

    OQS_init();

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
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

    static CanReassembler reassembler;

    canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        if (event.frame.canId != 0x601)
            return;

        if (reassembler.OnFrame(event.frame)){
            std::vector<uint8_t> ciphertext = reassembler.buffer;

            std::vector<uint8_t> shared_secret(kem->length_shared_secret);

            if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), sk.data()) != OQS_SUCCESS){
                std::cerr << "Error during decapsulation" << std::endl;
                return;
            }

            std::cout << "Shared secret calculated (" << shared_secret.size() << " byte): ";
            for (uint8_t b : shared_secret){
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            }
            std::cout << std::dec << std::endl;
            OQS_KEM_free(kem);
            done.store(true);
        }
    });

    canCtrl->Start();

    SendOverCan(canCtrl, 0x600, pk);
    std::cout << "Public key sent (" << pk.size() << " byte)" << std::endl;

    while (!done.load())
    {}
}
