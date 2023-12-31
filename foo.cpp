#include <cstdlib>
#include <iostream>
#include "websocat_transform.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <mutex>

using namespace CryptoPP;

std::mutex prng_mutex;
CryptoPP::AutoSeededRandomPool prng;

constexpr char KEYGEN_SALT[] = "FOTILE96_SALT!@#";
#define DEFAULT_KEY "<REPLACE_WITH_YOUR_PREDEFINED_KEY>"
#define ENV_KEY_NAME "WEBSOCAT_TRANSFORM_KEY"
std::unique_ptr<std::string> key;

class CryptoSession {
public:
    static CryptoSession *new_encode_session(const std::string &str_key) {
        byte iv[CryptoPP::ChaCha::IV_LENGTH];
        {
            std::lock_guard<std::mutex> _(prng_mutex);
            prng.GenerateBlock(iv, sizeof(iv));
        }
        return new CryptoSession(str_key, iv);
    }

    static CryptoSession *new_decode_session(const std::string &str_key) {
        return new CryptoSession(str_key);
    }

    const byte *get_iv() {
        return iv_;
    }

    int process(byte *buf, int len) {
        if (len <= 0)
            return 0;

        if (!inited_) {
            std::memcpy(iv_, buf, sizeof(iv_));
            std::memmove(buf, buf + sizeof(iv_), len - sizeof(iv_));
            len -= sizeof(iv_);
            enc_ = std::make_unique<ChaCha::Encryption>(key_, sizeof(key_), iv_);
            inited_ = true;
        }

        enc_->ProcessData(buf, buf, len);

        if (!first_packet_sent_) {
            std::memmove(buf + sizeof(iv_), buf, len);
            std::memcpy(buf, iv_, sizeof(iv_));
            len += sizeof(iv_);
            first_packet_sent_ = true;
        }

        return len;
    }


protected:
    byte key_[ChaCha::DEFAULT_KEYLENGTH];
    byte iv_[ChaCha::IV_LENGTH];
    bool inited_;
    bool first_packet_sent_;
    std::unique_ptr<ChaCha::Encryption> enc_;

    void generate_key_(const std::string &str_key) {
        HKDF<SHA256> hkdf;
        hkdf.DeriveKey(
                key_, sizeof(key_),
                reinterpret_cast<const byte *>(str_key.data()), str_key.length(),
                reinterpret_cast<const byte *>(KEYGEN_SALT), sizeof(KEYGEN_SALT),
                nullptr, 0
        );
    }

    explicit CryptoSession(const std::string &str_key, const byte *iv) : inited_(true), first_packet_sent_(false) {
        generate_key_(str_key);
        std::memcpy(iv_, iv, sizeof(iv_));
        enc_ = std::make_unique<ChaCha::Encryption>(key_, sizeof(key_), iv_);
    }

    explicit CryptoSession(const std::string &str_key) : inited_(false), first_packet_sent_(true) {
        generate_key_(str_key);
    }
};

std::map<size_t, std::unique_ptr<CryptoSession>> enc_session_map_;
std::mutex enc_session_map_mutex_;

DLLEXPORT size_t enc(unsigned char *buffer, size_t data_length, size_t buffer_capacity, size_t connection_number,
                     size_t packet_number) {
    if (buffer == nullptr)
        if (packet_number == 0) {
            std::lock_guard<std::mutex> _(enc_session_map_mutex_);
            if (enc_session_map_.count(connection_number) == 0) {
                enc_session_map_[connection_number] = std::unique_ptr<CryptoSession>(
                        CryptoSession::new_encode_session(*key));
            }
            return 0;
        } else {
            std::lock_guard<std::mutex> _(enc_session_map_mutex_);
            enc_session_map_.erase(connection_number);
            return 0;
        }
    else {
        CryptoSession *session = nullptr;
        {
            std::lock_guard<std::mutex> _(enc_session_map_mutex_);
            session = enc_session_map_[connection_number].get();
        }
        return session->process(buffer, data_length);
    }
}

std::map<size_t, std::unique_ptr<CryptoSession>> dec_session_map_;
std::mutex dec_session_map_mutex_;

DLLEXPORT size_t dec(unsigned char *buffer, size_t data_length, size_t buffer_capacity, size_t connection_number,
                     size_t packet_number) {
    if (buffer == nullptr)
        if (packet_number == 0) {
            std::lock_guard<std::mutex> _(dec_session_map_mutex_);
            if (dec_session_map_.count(connection_number) == 0) {
                dec_session_map_[connection_number] = std::unique_ptr<CryptoSession>(
                        CryptoSession::new_decode_session(*key));
            }
            return 0;
        } else {
            std::lock_guard<std::mutex> _(dec_session_map_mutex_);
            dec_session_map_.erase(connection_number);
            return 0;
        }
    else {
        CryptoSession *session = nullptr;
        {
            std::lock_guard<std::mutex> _(dec_session_map_mutex_);
            session = dec_session_map_[connection_number].get();
        }
        return session->process(buffer, data_length);
    }
}

static void init() __attribute__((constructor));

void init() {
    const char *env_key_ = std::getenv(ENV_KEY_NAME);
    if (env_key_ == nullptr || std::strlen(env_key_) <= 0) {
        key = std::make_unique<std::string>(DEFAULT_KEY);
        std::cerr << "Key not found in env, use default: " << DEFAULT_KEY << std::endl;
    } else {
        key = std::make_unique<std::string>(env_key_);
        std::cerr << "Key = " << *key << std::endl;
    }
}