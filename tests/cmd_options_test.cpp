#include <gtest/gtest.h>
#include "cmd_options.h"

TEST(ProgramOptions, Help) {
    const char* argv[] = {
        "CryptoGuard",
        "--help"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char**)argv), true);
}

TEST(ProgramOptions, CommandEncrypt) {
    const char* argv[] = {
        "CryptoGuard",
        "--command", "encrypt"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char**)argv), false);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, CommandDECRYPT) {
    const char* argv[] = {
        "CryptoGuard",
        "--command", "decrypt"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char**)argv), false);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, CommandChecksum) {
    const char* argv[] = {
        "CryptoGuard",
        "--command", "checksum"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char**)argv), false);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, CommandInvalidCmd) {
    const char* argv[] = {
        "CryptoGuard",
        "--command", "invalid"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(
        options.Parse(argc, (char**)argv),
        std::runtime_error
    );
}

TEST(ProgramOptions, OtherStuff) {
    const char* argv[] = {
        "CryptoGuard",
        "--input", "a.txt",
        "--output", "b.txt",
        "--password", "123",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char**)argv), false);
    ASSERT_EQ(options.GetInputFile(), "a.txt");
    ASSERT_EQ(options.GetOutputFile(), "b.txt");
    ASSERT_EQ(options.GetPassword(), "123");
}
