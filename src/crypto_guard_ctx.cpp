#include "crypto_guard_ctx.h"
#include <ios>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};



    struct CryptoGuardCtx::Impl{
        Impl(){
            OpenSSL_add_all_algorithms();
        }

        ~Impl(){
            EVP_cleanup();
        }

        using CtxGuard = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); })>;
        using MdCtxGuard = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* ctx) { EVP_MD_CTX_free(ctx); })>;

        enum Operation{
            Decrypt = 0,
            Encrypt = 1,
        };

        void processErrorOpenSSL(std::string_view description) const{
            std::stringstream ss;
            ss << description << " OpenSSL error code: " << ERR_get_error();
            throw std::runtime_error(ss.str());
        }

        void Process(Operation type, std::iostream &inStream, std::iostream &outStream, std::string_view password) const{
            constexpr size_t bufferSize = 16;
            std::vector<unsigned char> inBuf(bufferSize);
            std::vector<unsigned char> outBuf(bufferSize + EVP_MAX_BLOCK_LENGTH);
            int inlen, outlen;
            if(not inStream){
                throw std::runtime_error("Invalid input file!");
            }
            else if (not outStream){
                throw std::runtime_error("Invalid output file!");
            }

            auto params = CreateChiperParamsFromPassword(password);
            params.encrypt = static_cast<int>(type);
            CtxGuard ctx {EVP_CIPHER_CTX_new()};
            if(!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)){
                processErrorOpenSSL("Cipher initialization failed");
            }

            //https://docs.openssl.org/master/man3/EVP_EncryptInit/#examples:~:text=iv%200102030405060708%20%3Cfilename-,General%20encryption,-and%20decryption%20function
            for (;;)
            {
                inStream.read((char*)inBuf.data(), bufferSize);
                const auto inlen = inStream.gcount();
                if (inlen <= 0){
                    break;
                }

                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outlen, inBuf.data(), inlen)) {
                    processErrorOpenSSL("CipherUpdate");
                }
                outStream.write((char*)outBuf.data(), outlen);
            }
            if(!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outlen)){
                processErrorOpenSSL("Cipher finalization failed.");
            }
            outStream.write((char*)outBuf.data(), outlen);
        }

        void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const{
            Process(Encrypt, inStream, outStream, password);
        }
        void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const{
            Process(Decrypt, inStream, outStream, password);
        }
        std::string CalculateChecksum(std::iostream &inStream) const{
            const EVP_MD *md;
            constexpr size_t bufferSize = 16;
            std::vector<unsigned char> inBuf(bufferSize);
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len, i;
            if(not inStream){
                throw std::runtime_error("Invalid input file!");
            }
            md = EVP_get_digestbyname("sha256");
            if (md == NULL) {
                processErrorOpenSSL("Invalid digest!");
            }
            MdCtxGuard mdctx{EVP_MD_CTX_new()};
            if (not mdctx) {
                processErrorOpenSSL("Message digest create failed");
            }
            if (!EVP_DigestInit_ex2(mdctx.get(), md, NULL)) {
                processErrorOpenSSL("Message digest initialization failed");
            }
            for (;;)
            {
                inStream.read((char*)inBuf.data(), bufferSize);
                const auto inlen = inStream.gcount();
                if (inlen <= 0){
                    break;
                }
                if (!EVP_DigestUpdate(mdctx.get(), inBuf.data(), inlen)) {
                    processErrorOpenSSL("Message digest update failed");
                }
            }
            if (!EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len)) {
                processErrorOpenSSL("Message digest finalization failed.");
            }
            std::stringstream ss;
            ss << "0x" << std::hex << std::uppercase;
            for (i = 0; i < md_len; i++)
                ss << (int)md_value[i];
            return ss.str();
        }

        AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const {
            AesCipherParams params;
            constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

            int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                        reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                        params.key.data(), params.iv.data());

            if (result == 0) {
                processErrorOpenSSL("Failed to create a key from password");
            }

            return params;
        }

    };

    void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const{
        pImpl_->EncryptFile(inStream,outStream, password);
    }

    void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const{
        pImpl_->DecryptFile(inStream,outStream, password);
    }

    std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const{
        return pImpl_->CalculateChecksum(inStream);
    }

    CryptoGuardCtx::CryptoGuardCtx(): pImpl_(std::make_unique<Impl>()) {}
    CryptoGuardCtx::~CryptoGuardCtx() = default;
} // namespace CryptoGuard
