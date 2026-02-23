#include <silkit/SilKit.hpp>
#include <silkit/services/can/all.hpp>
#include <ecusim/CanTransport.hpp>

#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <ncurses.h>

using namespace SilKit;
using namespace SilKit::Services::Can;

std::atomic<uint16_t> g_acceleration(0);
std::atomic<bool> g_simulatorActive(true);

void keyboardInputThread() {
    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);

    const uint16_t step = 1;
    const uint16_t max_val = 25;
    const uint16_t min_val = 0;
    const char target_key = 'w';

    while (g_simulatorActive) {
        int ch = getch();
        if (ch == target_key) {
            uint16_t val = g_acceleration.load();
            if (val < max_val) g_acceleration = val + step;
        } else {
            uint16_t val = g_acceleration.load();
            if (val >= 2 * step) {
                g_acceleration = val - 2 * step;
            } else {
                g_acceleration = 0;
            }
        }
        if (ch == 'q') g_simulatorActive = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    endwin();
}

int main() {

    auto config = SilKit::Config::ParticipantConfigurationFromFile("silkit_config.yaml");
    auto participant = SilKit::CreateParticipant(config, "SIMULATOR");
    auto* canCtrl = participant->CreateCanController("SIMULATOR_CTRL", "CAN1");

    static CanReassembler reassembler;
    std::atomic<uint16_t> rpm{0}, spd{0}, load{0}, gear{0};
    uint8_t key[32] = {0x69, 0xd3, 0x68, 0x1a, 0x72, 0x28, 0x2e, 0x24,
        0x42, 0xb2, 0x6a, 0xfa, 0xed, 0x94, 0x48, 0xbe,
        0x3c, 0x64, 0x56, 0xdf, 0xa1, 0x32, 0xf8, 0x6d,
        0x4f, 0x96, 0x9a, 0xfa, 0xfc, 0xad, 0x35, 0x5c};

    std::thread inputThread(keyboardInputThread);

     canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId) {
        case 0x300:
            if (reassembler.OnFrame(event.frame)){
                rpm.store(decode(decrypt_aes(reassembler.buffer, key)));
            }
            break;
        case 0x400:
            if (reassembler.OnFrame(event.frame)){
                spd.store(decode(decrypt_aes(reassembler.buffer, key)));
            }
            break;
        case 0x500:
            if (reassembler.OnFrame(event.frame)){
                load.store(decode(decrypt_aes(reassembler.buffer, key)));
            }
            break;
        case 0x600:
            if (reassembler.OnFrame(event.frame)){
                gear.store(decode(decrypt_aes(reassembler.buffer, key)));
            }
            break;
        }
    });

    canCtrl->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    while (g_simulatorActive) {
        uint16_t acc = g_acceleration.load()*4;
        uint8_t key[32] = {0x69, 0xd3, 0x68, 0x1a, 0x72, 0x28, 0x2e, 0x24,
            0x42, 0xb2, 0x6a, 0xfa, 0xed, 0x94, 0x48, 0xbe,
            0x3c, 0x64, 0x56, 0xdf, 0xa1, 0x32, 0xf8, 0x6d,
            0x4f, 0x96, 0x9a, 0xfa, 0xfc, 0xad, 0x35, 0x5c};

        std::vector<uint8_t> accBytes = encrypt_aes(encode(acc), key);
        SendOverCan(canCtrl, 0x200, accBytes);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        float speed = spd.load()/10.0f;
        float stress = load.load()/10.0f;
        mvprintw(0, 0, "Accelerazione: %.1u  ", g_acceleration.load()*4);
        mvprintw(1, 0, "Giri: %.1u    ", rpm.load());
        mvprintw(2, 0, "Velocità: %.1f    ", speed);
        mvprintw(3, 0, "Sforzo motore: %.1f     ", stress);
        mvprintw(4, 0, "Marcia: %.1u  ", gear.load());
        mvprintw(5, 0, "Premi '%c' per accelerare, 'q' per uscire.", 'w'); 
        refresh();
    }
    inputThread.join();
    std::vector<uint8_t> stopData = {0x01};
    SendOverCan(canCtrl, 0x999, stopData);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    return 0;
} 
