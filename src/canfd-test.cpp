#include <iostream>
#include <vector>
#include <chrono>
#include <thread>

#include "silkit/SilKit.hpp"
#include "silkit/services/can/all.hpp"

using namespace SilKit::Services::Can;
using namespace std::chrono_literals;

int main() {
    auto config = SilKit::Config::ParticipantConfigurationFromFile("silkit_config.yaml");
    auto participant = SilKit::CreateParticipant(config, "CanWriter");
    auto* canController = participant->CreateCanController("CAN1", "CAN1");

    canController->Start();

    std::vector<uint8_t> payload = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };

    CanFrame fdFrame{};
    fdFrame.canId = 0x123;

    fdFrame.flags = static_cast<CanFrameFlagMask>(CanFrameFlag::Fdf)
    | static_cast<CanFrameFlagMask>(CanFrameFlag::Brs);

    fdFrame.dataField = SilKit::Util::Span<const uint8_t>(payload.data(), payload.size());

    fdFrame.dlc = static_cast<uint16_t>(payload.size());

    std::cout << "Invio frame CAN FD (FDF+BRS) su CAN1..." << std::endl;

    while (true) {
        canController->SendFrame(fdFrame);
        std::this_thread::sleep_for(1s);
    }

    return 0;
}
