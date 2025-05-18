#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <print>
#include <stdexcept>
#include <fstream>





int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        if(options.Parse(argc, argv)){
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            {
                std::fstream in(options.GetInputFile(), std::ios::in | std::ios::binary);
                std::fstream out(options.GetOutputFile(), std::ios::out | std::ios::binary);

                cryptoCtx.EncryptFile(in, out, options.GetPassword());
                std::print("File encoded successfully\n");
                break;
            }
        case COMMAND_TYPE::DECRYPT:
            {
                std::fstream in(options.GetInputFile(), std::ios::in | std::ios::binary);
                std::fstream out(options.GetOutputFile(), std::ios::out | std::ios::binary);

                cryptoCtx.DecryptFile(in, out, options.GetPassword());
                std::print("File decoded successfully\n");
                break;
            }
        case COMMAND_TYPE::CHECKSUM:
            {
                std::fstream in(options.GetInputFile(), std::ios::in | std::ios::binary);
                std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(in));
            }
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
