#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>

using namespace SilKit;
using namespace SilKit::Services::Can;

void SendOverCan(ICanController* canCtrl, uint32_t canId, const std::vector<uint8_t>& data)
{
    std::array<uint8_t, 64> buffer;
    CanFrame frame{};
    frame.canId = canId;
    if(data.size() <= 7){
        frame.dlc = 8;
    }
    else if(data.size() <= 62){
        frame.flags = static_cast<CanFrameFlagMask>(CanFrameFlag::Fdf)
        | static_cast<CanFrameFlagMask>(CanFrameFlag::Brs);
        frame.dlc = 64;
    }
    frame.dataField = Util::MakeSpan(buffer);

    if (data.size() <= 7){
        buffer[0] = 0x00;
        std::copy(data.begin(), data.end(), buffer.begin() + 1);
        if (data.size() < 7){
            std::fill(buffer.begin() + 1 + data.size(), buffer.end(), 0);
        }
        canCtrl->SendFrame(frame);
        return;
    }
    else if(data.size() <= 62){
        buffer[0] = 0x00;
        std::copy(data.begin(), data.end(), buffer.begin() + 1);
        if (data.size() < 62){
            std::fill(buffer.begin() + 1 + data.size(), buffer.end(), 0);
        }
        canCtrl->SendFrame(frame);
        return;
    }

    uint8_t seq = 0;
    size_t offset = 0;
    uint16_t totalSize = static_cast<uint16_t>(data.size());

    buffer[0] = 0x01;
    buffer[1] = seq++;
    buffer[2] = static_cast<uint8_t>((totalSize >> 8) & 0xFF);
    buffer[3] = static_cast<uint8_t>(totalSize & 0xFF);
    size_t chunk = std::min(data.size(), size_t(frame.dlc - 4));
    std::copy(data.begin(), data.begin() + chunk, buffer.begin() + 4);
    std::fill(buffer.begin() + 4 + chunk, buffer.end(), 0);
    canCtrl->SendFrame(frame);
    offset += chunk;

    while (offset < data.size()){
        buffer[0] = 0x02;
        buffer[1] = seq++;
        chunk = std::min(data.size() - offset, size_t(frame.dlc - 2));
        std::copy(data.begin() + offset, data.begin() + offset + chunk, buffer.begin() + 2);
        std::fill(buffer.begin() + 2 + chunk, buffer.end(), 0);
        canCtrl->SendFrame(frame);
        offset += chunk;
    }

    buffer[0] = 0x03;
    buffer[1] = seq;
    std::fill(buffer.begin() + 2, buffer.end(), 0);
    canCtrl->SendFrame(frame);
}

struct CanReassembler
{
    std::vector<uint8_t> buffer;
    uint16_t totalSize = 0;
    bool receiving = false;
    uint8_t expectedSeq = 0;

    bool OnFrame(const CanFrame& f)
    {
        uint8_t type = f.dataField[0];
        uint8_t seq = f.dataField[1];

        if (type == 0x00){
            buffer.clear();
            AppendSF(f);
            return true;
        }

        if (type == 0x01){
            totalSize = (static_cast<uint16_t>(f.dataField[2]) << 8) | static_cast<uint16_t>(f.dataField[3]);
            buffer.clear();
            buffer.reserve(totalSize);
            AppendFF(f);
            receiving = true;
            expectedSeq = seq;
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

    void AppendSF(const CanFrame& f)
    {
        for (int i = 1; i < f.dlc; ++i)
            buffer.push_back(f.dataField[i]);
    }

    void AppendFF(const CanFrame& f)
    {
        for (int i = 4; i < f.dlc; ++i)
            if (buffer.size() < totalSize){
                buffer.push_back(f.dataField[i]);
    }
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

std::vector<uint8_t> encode(uint16_t val){
    std::vector<uint8_t> valBytes = {static_cast<uint8_t>((val >> 8) & 0xFF), static_cast<uint8_t>(val & 0xFF)};
    return valBytes; 
}

uint16_t decode(std::vector<uint8_t> valBytes){
    uint16_t val = (static_cast<uint16_t>(valBytes[0]) << 8) |  static_cast<uint16_t>(valBytes[1]);
    return val;
}

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
