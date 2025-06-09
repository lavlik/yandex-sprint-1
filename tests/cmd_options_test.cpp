#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(ProgramOptions, Help) {
    static constexpr std::array argv = {"CryptoGuard", "--help"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char **)argv.data()), true);
}

TEST(ProgramOptions, CommandEncrypt) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "encrypt", "--input", "a.txt", "--output", "b.txt", "--password", "123",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char **)argv.data()), false);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    ASSERT_EQ(options.GetInputFile(), "a.txt");
    ASSERT_EQ(options.GetOutputFile(), "b.txt");
    ASSERT_EQ(options.GetPassword(), "123");
}

TEST(ProgramOptions, CommandDECRYPT) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "decrypt", "--input", "a.txt", "--output", "b.txt", "--password", "123",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char **)argv.data()), false);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    ASSERT_EQ(options.GetInputFile(), "a.txt");
    ASSERT_EQ(options.GetOutputFile(), "b.txt");
    ASSERT_EQ(options.GetPassword(), "123");
}

TEST(ProgramOptions, CommandChecksum) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "checksum", "--input", "a.txt",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_EQ(options.Parse(argc, (char **)argv.data()), false);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    ASSERT_EQ(options.GetInputFile(), "a.txt");
}

TEST(ProgramOptions, CommandInvalidCmd) {
    static constexpr std::array argv = {"CryptoGuard", "--command", "invalid"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char **)argv.data()), std::runtime_error);
}

TEST(ProgramOptions, NoCommand) {
    static constexpr std::array argv = {"CryptoGuard", "--input", "a.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char **)argv.data()), std::runtime_error);
}

TEST(ProgramOptions, NoInput) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "checksum", "--output", "b.txt",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char **)argv.data()), std::runtime_error);
}

TEST(ProgramOptions, NoPassword) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "encrypt", "--input", "a.txt", "--output", "b.txt",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char **)argv.data()), std::runtime_error);
}

TEST(ProgramOptions, ExtraPassword) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "checksum", "--input", "a.txt", "--password", "123",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char **)argv.data()), std::runtime_error);
}

TEST(ProgramOptions, ExtraOutput) {
    static constexpr std::array argv = {
        "CryptoGuard", "--command", "checksum", "--input", "a.txt", "--output", "b.txt",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char **)argv.data()), std::runtime_error);
}
