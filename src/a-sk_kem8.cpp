#include <silkit/SilKit.hpp>
#include <silkit/services/can/all.hpp>
#include <oqs/oqs.h>
#include <ecusim/CanTransport.hpp>

#include <algorithm>
#include <array>
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
    auto participant = SilKit::CreateParticipant(config, "ECU_A");
    auto* canCtrl = participant->CreateCanController("CAN_CTRL_A", "CAN1");

    static CanReassembler reassembler;

    canCtrl->AddFrameHandler([canCtrl](ICanController*, const CanFrameEvent& event)
        {
            if (event.frame.canId != 0x600)
                return;

            if (reassembler.OnFrame(event.frame)){
                std::vector<uint8_t> pk = reassembler.buffer;
                std::cout << "Public key received: " << pk.size() << " byte" << std::endl;

                OQS_KEM* kem = OQS_KEM_new("Kyber512");
                if (!kem){
                    std::cerr << "Error in KEM creation" << std::endl;
                    return;
                }

                std::vector<uint8_t> ciphertext(kem->length_ciphertext);
                std::vector<uint8_t> shared_secret(kem->length_shared_secret);

                if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(), pk.data()) != OQS_SUCCESS){
                    std::cerr << "Error during Encapsulation" << std::endl;
                    return;
                }

                SendOverCan(canCtrl, 0x601, ciphertext);

                std::cout << "Ciphertext sent (" << ciphertext.size() << " byte)" << std::endl;
                std::cout << "Shared secret calculated (" << shared_secret.size() << " byte): ";
                for (uint8_t b : shared_secret){
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                }

                std::cout << std::dec << std::endl;
                OQS_KEM_free(kem);
            }
        });

    canCtrl->Start();

    while (true)
    {}
}
