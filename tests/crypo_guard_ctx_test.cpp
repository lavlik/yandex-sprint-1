#include <gtest/gtest.h>
#include "crypto_guard_ctx.h"
#include <sstream>

TEST(TestEncrypt, EncryptChangesContent) {
    const std::string original = "123";
    const std::string password = "password";

    std::stringstream in(original);
    std::stringstream out;
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    cryptoCtx.EncryptFile(in, out, password);

    EXPECT_FALSE(out.str().empty());
    EXPECT_NE(out.str(), original);
    EXPECT_NE(out.str().find(original), 0);
}

TEST(TestEncrypt, DifferentPasswordsProduceDifferentOutput) {
    const std::string text = "123";

    std::stringstream in1(text);
    std::stringstream out1;
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(in1, out1, "password1");

    std::stringstream in2(text);
    std::stringstream out2;
    cryptoCtx.EncryptFile(in2, out2, "password2");

    EXPECT_NE(out1.str(), out2.str());
}

TEST(TestEncrypt, InvalidPasswordHandling) {
    const std::string original = "123";
    std::stringstream in(original);
    const std::string password = "password";
    std::stringstream out;
    out.setstate(std::_Ios_Iostate::_S_failbit);
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.EncryptFile(in, out, password), std::runtime_error);
}


class CryptoGuardCtxTest : public ::testing::Test {
protected:
    void SetUp() override {
        const std::string original = "123";
        const std::string password = "password";

        std::stringstream encryptIn(original);
        std::stringstream encryptedData;
        ctx.EncryptFile(encryptIn, encryptedData, password);

        this->encryptedData = encryptedData.str();
        this->password = password;
        this->originalText = original;
    }

    CryptoGuard::CryptoGuardCtx ctx;
    std::string encryptedData;
    std::string password;
    std::string originalText;
};

TEST_F(CryptoGuardCtxTest, DecryptValidDataReturnsOriginal) {
    std::stringstream in(encryptedData);
    std::stringstream out;

    ctx.DecryptFile(in, out, password);

    EXPECT_EQ(out.str(), originalText);
}

TEST_F(CryptoGuardCtxTest, DecryptWithInvalidPasswordFails) {
    std::stringstream in(encryptedData);
    std::stringstream out;

    ASSERT_THROW(
        ctx.DecryptFile(in, out, "invalid_password");,
        std::runtime_error
    );
    // ctx.DecryptFile(in, out, "invalid_password");

    // EXPECT_NE(out.str(), originalText);
}

TEST_F(CryptoGuardCtxTest, DecryptInvalidInputThrows) {
    std::stringstream in;
    in.setstate(std::_Ios_Iostate::_S_badbit);
    std::stringstream out;

    ASSERT_THROW(
        ctx.DecryptFile(in, out, password),
        std::runtime_error
    );
}


class CryptoGuardCtxSumTest : public CryptoGuardCtxTest {
protected:
    void SetUp() override {
        CryptoGuardCtxTest::SetUp();
        std::stringstream in(encryptedData);
        std::stringstream out;
        ctx.DecryptFile(in, out, password);
        this->decryptedData = out.str();
    }
    std::string decryptedData;
};

TEST_F(CryptoGuardCtxSumTest, CheckSum) {
    std::stringstream in(encryptedData);
    std::stringstream out(decryptedData);
    std::stringstream original(originalText);

    const auto csBefore = ctx.CalculateChecksum(original);
    const auto csEncrypted = ctx.CalculateChecksum(in);
    const auto csAfter = ctx.CalculateChecksum(out);
    EXPECT_EQ(csBefore, csAfter);
    EXPECT_NE(csBefore, csEncrypted);
}

TEST_F(CryptoGuardCtxSumTest, CheckSumInvalidInputThrows) {
    std::stringstream in;
    in.setstate(std::_Ios_Iostate::_S_badbit);

    ASSERT_THROW( ctx.CalculateChecksum(in), std::runtime_error);
}
