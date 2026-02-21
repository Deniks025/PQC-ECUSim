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
    auto participant = SilKit::CreateParticipant(config, "CanXlWriter");

    auto* canController = participant->CreateCanController("CAN1", "CAN1");
    canController->Start();

    std::vector<uint8_t> xlPayload(128, 0xDE);

    CanFrame xlFrame{};
    xlFrame.canId = 0x1FF;

    xlFrame.flags = static_cast<CanFrameFlagMask>(CanFrameFlag::Xlf)
    | static_cast<CanFrameFlagMask>(CanFrameFlag::Sec);

    xlFrame.sdt = 0x01;
    xlFrame.vcid = 0x02;
    xlFrame.af = 0x12345678;
    xlFrame.dataField = SilKit::Util::Span<const uint8_t>(xlPayload.data(), xlPayload.size());

    xlFrame.dlc = static_cast<uint16_t>(xlPayload.size());

    std::cout << "Invio frame CAN XL (XLF+SEC) su CAN1 - Size: " << xlPayload.size() << " bytes" << std::endl;

    while (true) {
        canController->SendFrame(xlFrame);
        std::this_thread::sleep_for(1s);
    }

    return 0;
}
