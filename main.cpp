#include <silkit/SilKit.hpp>
#include <silkit/services/can/all.hpp>
#include <ecusim/CanTransport.hpp>
#include <oqs/oqs.h>

#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <ncurses.h>
#include <iomanip>

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

int main()
{
    auto config = SilKit::Config::ParticipantConfigurationFromFile("silkit_config.yaml");
    auto participant = SilKit::CreateParticipant(config, "SIMULATOR");
    auto* canCtrl = participant->CreateCanController("SIMULATOR_CTRL", "CAN1");

    OQS_init();
    OQS_KEM* kem = OQS_KEM_new("Kyber512");

    static CanReassembler reasPK;
    static CanReassembler reasKey;
    static CanReassembler reasRpm;
    static CanReassembler reasSpd;
    static CanReassembler reasMotor;
    static CanReassembler reasGear;

    std::atomic<uint16_t> rpm{0}, spd{0}, load{0}, gear{0};
    std::vector<uint8_t> key(kem->length_shared_secret);
    std::vector<uint8_t> clusterKey(32);
    std::atomic<bool> secureCluster{false};
    std::thread inputThread(keyboardInputThread);

     canCtrl->AddFrameHandler([&](ICanController*, const CanFrameEvent& event)
    {
        switch (event.frame.canId) {
        case 0x091:
            if (reasPK.OnFrame(event.frame)) {
                std::vector<uint8_t> pk = reasPK.buffer;
                if (!kem) {
                    std::cerr << "Error in KEM creation" << std::endl;
                    return;
                }
                std::vector<uint8_t> ciphertext(kem->length_ciphertext);
                if (OQS_KEM_encaps(kem, ciphertext.data(), key.data(), pk.data()) != OQS_SUCCESS) {
                    std::cerr << "Error during Encapsulation" << std::endl;
                    OQS_KEM_free(kem);
                    return;
                }
                SendOverCan(canCtrl, 0x202, ciphertext);
            }
            break;
        case 0x25:
            if (reasKey.OnFrame(event.frame)) {
                clusterKey = decrypt_aes(reasKey.buffer, key);
                secureCluster = true;
                SendOverCan(canCtrl, 0x900, clusterKey);
            }
            break;
        case 0x304:
            if (reasRpm.OnFrame(event.frame)) {
                rpm.store(decode(decrypt_aes(reasRpm.buffer, clusterKey)));
            }
            break;
        case 0x404:
            if (reasSpd.OnFrame(event.frame)) {
                spd.store(decode(decrypt_aes(reasSpd.buffer, clusterKey)));
            }
            break;
        case 0x504:
            if (reasMotor.OnFrame(event.frame)) {
                load.store(decode(decrypt_aes(reasMotor.buffer, clusterKey)));
            }
            break;
        case 0x604:
            if (reasGear.OnFrame(event.frame)) {
                gear.store(decode(decrypt_aes(reasGear.buffer, clusterKey)));
            }
            break;
        }
    });

    canCtrl->Start();
    SendOverCan(canCtrl, 0x200, {0x01});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    while (g_simulatorActive) {
        uint16_t acc = g_acceleration.load()*4;
        if(secureCluster.load()) {
            SendOverCan(canCtrl, 0x204, encrypt_aes(encode(acc), clusterKey));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        float speed = spd.load()/10.0f;
        float stress = load.load()/10.0f;
        mvprintw(0, 0, "Accelerazione: %-3.1u  ", g_acceleration.load()*4);
        mvprintw(1, 0, "Giri: %-6.1u    ", rpm.load());
        mvprintw(2, 0, "Velocità: %-6.1f    ", speed);
        mvprintw(3, 0, "Sforzo motore: %-6.1f     ", stress);
        mvprintw(4, 0, "Marcia: %.1u  ", gear.load());
        mvprintw(5, 0, "Premi '%c' per accelerare, 'q' per uscire.", 'w');
        refresh();
    }
    inputThread.join();
    std::vector<uint8_t> stopData = {0x01};
    SendOverCan(canCtrl, 0x999, stopData);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    OQS_KEM_free(kem);
    return 0;
} 
