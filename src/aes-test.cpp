#include <iostream>
#include <vector>
#include <string>

#include "silkit/SilKit.hpp"
#include "silkit/services/can/all.hpp"
#include "oqs/oqs.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <ecusim/CanTransport.hpp>

using namespace SilKit::Services::Can;

std::vector<uint8_t> encrypt_aes(const std::vector<uint8_t>& plaintext, const uint8_t* key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    std::vector<uint8_t> iv(16);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Errore nella generazione del numero casuale");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    std::vector<uint8_t> final_packet;
    final_packet.insert(final_packet.end(), iv.begin(), iv.end());
    final_packet.insert(final_packet.end(), ciphertext.begin(), ciphertext.end());

    EVP_CIPHER_CTX_free(ctx);
    return final_packet;
}

#include <openssl/evp.h>
#include <vector>
#include <stdexcept>

std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t>& combined_data, const uint8_t* key) {
    if (combined_data.size() < 32) {
        throw std::runtime_error("Dati insufficienti per la decriptazione (pacchetto troppo corto)");
    }

    uint8_t iv[16];
    std::copy(combined_data.begin(), combined_data.begin() + 16, iv);

    std::vector<uint8_t> ciphertext(combined_data.begin() + 16, combined_data.end());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore nell'inizializzazione della decriptazione");
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore durante il processamento dei dati criptati");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore nella finalizzazione (chiave errata o padding corrotto)");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

int main() {
    auto config = SilKit::Config::ParticipantConfigurationFromFile("silkit_config.yaml");
    auto participant = SilKit::CreateParticipant(config, "AesSender");
    auto* canController = participant->CreateCanController("CAN1", "CAN1");
    canController->Start();

    uint8_t key[32] = {0x00};

    std::string secret_msg = "Messaggio Segreto PQC";
    std::vector<uint8_t> plaintext(secret_msg.begin(), secret_msg.end());

    std::cout << "Criptazione in corso..." << std::endl;
    std::vector<uint8_t> encrypted_data = encrypt_aes(plaintext, key);

    std::cout << "Invio dati criptati (frammentati) su CAN1..." << std::endl;

    SendOverCan(canController, 0x500, encrypted_data);

    return 0;
}
