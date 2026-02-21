#include <silkit/SilKit.hpp>
#include <silkit/services/can/ICanController.hpp>
#include <silkit/services/can/CanDatatypes.hpp>
#include <oqs/oqs.h>

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

void SendOverCan(ICanController* canCtrl, uint32_t canId, const std::vector<uint8_t>& data)
{
    static std::array<uint8_t, 64> buffer;
    CanFrame fdFrame{};
    fdFrame.canId = canId;
    fdFrame.flags = static_cast<CanFrameFlagMask>(CanFrameFlag::Fdf)
    | static_cast<CanFrameFlagMask>(CanFrameFlag::Brs);
    fdFrame.dlc = 64;
    fdFrame.dataField = Util::MakeSpan(buffer);

    uint8_t seq = 0;
    size_t offset = 0;

    buffer[0] = 0x01;
    buffer[1] = seq++;
    size_t chunk = std::min(data.size(), size_t(62));
    std::copy(data.begin(), data.begin() + chunk, buffer.begin() + 2);
    std::fill(buffer.begin() + 2 + chunk, buffer.end(), 0);
    canCtrl->SendFrame(fdFrame);
    offset += chunk;

    while (offset < data.size()){
        buffer[0] = 0x02;
        buffer[1] = seq++;
        chunk = std::min(data.size() - offset, size_t(62));
        std::copy(data.begin() + offset, data.begin() + offset + chunk, buffer.begin() + 2);
        std::fill(buffer.begin() + 2 + chunk, buffer.end(), 0);
        canCtrl->SendFrame(fdFrame);
        offset += chunk;
    }

    buffer[0] = 0x03;
    buffer[1] = seq;
    std::fill(buffer.begin() + 2, buffer.end(), 0);
    canCtrl->SendFrame(fdFrame);
}

struct CanReassembler
{
    std::vector<uint8_t> buffer;
    bool receiving = false;
    uint8_t expectedSeq = 0;

    bool OnFrame(const CanFrame& f)
    {
        uint8_t type = f.dataField[0];
        uint8_t seq = f.dataField[1];

        if (type == 0x01){
            buffer.clear();
            receiving = true;
            expectedSeq = seq;
            Append(f);
            return false;
        }
        if (!receiving || seq != expectedSeq + 1){
            Reset();
            return false;
        }
        expectedSeq = seq;
        if (type == 0x02){
            Append(f);
            return false;
        }
        if (type == 0x03){
            receiving = false;
            return true;
        }
        return false;
    }

    void Append(const CanFrame& f)
    {
        for (int i = 2; i < f.dlc; ++i)
            buffer.push_back(f.dataField[i]);
    }

    void Reset()
    {
        receiving = false;
        buffer.clear();
    }
};

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

            if (OQS_KEM_decaps(kem,
                shared_secret.data(),
                               ciphertext.data(),
                               sk.data()) != OQS_SUCCESS){
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
