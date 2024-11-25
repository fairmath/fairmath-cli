#pragma once

#include "openfhe/pke/cryptocontext-ser.h"

namespace cli
{

namespace utils
{

template <typename CryptoObjectType>
void deserialize(const std::string& path, std::shared_ptr<CryptoObjectType>& cryptoObject)
{
    if (!lbcrypto::Serial::DeserializeFromFile(path, cryptoObject, lbcrypto::SerType::BINARY))
    {
        throw std::runtime_error("Unable to deserialize " + path);
    }
}

template <typename CryptoObjectType>
void serialize(const std::string& path, const std::shared_ptr<CryptoObjectType>& cryptoObject)
{
    if (!lbcrypto::Serial::SerializeToFile(path, cryptoObject, lbcrypto::SerType::BINARY))
    {
        throw std::runtime_error("Unable to serialize " + path);
    }
}

void serialize(const std::string& path,
    bool (*serializeFunc)(std::ostream&, const lbcrypto::SerType::SERBINARY&, std::string))
{
    std::ofstream ofs(path, std::ios::out | std::ios::binary);
    if (ofs.is_open())
    {
        if (!serializeFunc(ofs, lbcrypto::SerType::BINARY, ""))
        {
            ofs.close();
            throw std::runtime_error("Unable to serialize " + path);
        }
        ofs.close();
    }
    else
    {
        throw std::runtime_error("Unable to open " + path + " file for writing serialization");
    }
}

[[nodiscard]] constexpr uint32_t strHash(const std::string_view data) noexcept
{
    uint32_t hash = 5381;
    for (const char c : data)
    {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
    }
    return hash;
}

[[nodiscard]] lbcrypto::SecretKeyDist getSecretKeyDist(const std::string_view secretKeyDist)
{
    switch (strHash(secretKeyDist))
    {
        case strHash("GAUSSIAN"): return lbcrypto::SecretKeyDist::GAUSSIAN;
        case strHash("UNIFORM_TERNARY"): return lbcrypto::SecretKeyDist::UNIFORM_TERNARY;
        case strHash("SPARSE_TERNARY"): return lbcrypto::SecretKeyDist::SPARSE_TERNARY;
        default: throw std::runtime_error("SecretKeyDist is not supported");
    }
}

[[nodiscard]] lbcrypto::KeySwitchTechnique getKeySwitchTechnique(const std::string_view keySwitchTechnique)
{
    switch (strHash(keySwitchTechnique))
    {
        case strHash("INVALID_KS_TECH"): return lbcrypto::KeySwitchTechnique::INVALID_KS_TECH;
        case strHash("BV"): return lbcrypto::KeySwitchTechnique::BV;
        case strHash("HYBRID"): return lbcrypto::KeySwitchTechnique::HYBRID;
        default: throw std::runtime_error("KeySwitchTechnique is not supported");
    }
}

[[nodiscard]] lbcrypto::ScalingTechnique getScalingTechnique(const std::string_view scalingTechnique)
{
    switch (strHash(scalingTechnique))
    {
        case strHash("FIXEDMANUAL"): return lbcrypto::ScalingTechnique::FIXEDMANUAL;
        case strHash("FIXEDAUTO"): return lbcrypto::ScalingTechnique::FIXEDAUTO;
        case strHash("FLEXIBLEAUTO"): return lbcrypto::ScalingTechnique::FLEXIBLEAUTO;
        case strHash("FLEXIBLEAUTOEXT"): return lbcrypto::ScalingTechnique::FLEXIBLEAUTOEXT;
        case strHash("NORESCALE"): return lbcrypto::ScalingTechnique::NORESCALE;
        case strHash("INVALID_RS_TECHNIQUE"): return lbcrypto::ScalingTechnique::INVALID_RS_TECHNIQUE;
        default: throw std::runtime_error("ScalingTechnique is not supported");
    }
}

[[nodiscard]] lbcrypto::SecurityLevel getSecurityLevel(const std::string_view securityLevel)
{
    switch (strHash(securityLevel))
    {
        case strHash("HEStd_128_classic"): return lbcrypto::SecurityLevel::HEStd_128_classic;
        case strHash("HEStd_192_classic"): return lbcrypto::SecurityLevel::HEStd_192_classic;
        case strHash("HEStd_256_classic"): return lbcrypto::SecurityLevel::HEStd_256_classic;
        case strHash("HEStd_128_quantum"): return lbcrypto::SecurityLevel::HEStd_128_quantum;
        case strHash("HEStd_192_quantum"): return lbcrypto::SecurityLevel::HEStd_192_quantum;
        case strHash("HEStd_256_quantum"): return lbcrypto::SecurityLevel::HEStd_256_quantum;
        case strHash("HEStd_NotSet"): return lbcrypto::SecurityLevel::HEStd_NotSet;
        default: throw std::runtime_error("SecurityLevel is not supported");
    }
}

[[nodiscard]] lbcrypto::EncryptionTechnique getEncryptionTechnique(const std::string_view encryptionTechnique)
{
    switch (strHash(encryptionTechnique))
    {
        case strHash("STANDARD"): return lbcrypto::EncryptionTechnique::STANDARD;
        case strHash("EXTENDED"): return lbcrypto::EncryptionTechnique::EXTENDED;
        default: throw std::runtime_error("EncryptionTechnique is not supported");
    }
}

[[nodiscard]] lbcrypto::MultiplicationTechnique getMultiplicationTechnique(const std::string_view multiplicationTechnique)
{
    switch (strHash(multiplicationTechnique))
    {
        case strHash("BEHZ"): return lbcrypto::MultiplicationTechnique::BEHZ;
        case strHash("HPS"): return lbcrypto::MultiplicationTechnique::HPS;
        case strHash("HPSPOVERQ"): return lbcrypto::MultiplicationTechnique::HPSPOVERQ;
        case strHash("HPSPOVERQLEVELED"): return lbcrypto::MultiplicationTechnique::HPSPOVERQLEVELED;
        default: throw std::runtime_error("MultiplicationTechnique is not supported");
    }
}

[[nodiscard]] lbcrypto::ProxyReEncryptionMode getProxyReEncryptionMode(const std::string_view proxyReEncryptionMode)
{
    switch (strHash(proxyReEncryptionMode))
    {
        case strHash("NOT_SET"): return lbcrypto::ProxyReEncryptionMode::NOT_SET;
        case strHash("INDCPA"): return lbcrypto::ProxyReEncryptionMode::INDCPA;
        case strHash("FIXED_NOISE_HRA"): return lbcrypto::ProxyReEncryptionMode::FIXED_NOISE_HRA;
        case strHash("NOISE_FLOODING_HRA"): return lbcrypto::ProxyReEncryptionMode::NOISE_FLOODING_HRA;
        default: throw std::runtime_error("ProxyReEncryptionMode is not supported");
    }
}

[[nodiscard]] lbcrypto::MultipartyMode getMultipartyMode(const std::string_view multipartyMode)
{
    switch (strHash(multipartyMode))
    {
        case strHash("INVALID_MULTIPARTY_MODE"): return lbcrypto::MultipartyMode::INVALID_MULTIPARTY_MODE;
        case strHash("FIXED_NOISE_MULTIPARTY"): return lbcrypto::MultipartyMode::FIXED_NOISE_MULTIPARTY;
        case strHash("NOISE_FLOODING_MULTIPARTY"): return lbcrypto::MultipartyMode::NOISE_FLOODING_MULTIPARTY;
        default: throw std::runtime_error("MultipartyMode is not supported");
    }
}

[[nodiscard]] lbcrypto::ExecutionMode getExecutionMode(const std::string_view executionMode)
{
    switch (strHash(executionMode))
    {
        case strHash("EXEC_EVALUATION"): return lbcrypto::ExecutionMode::EXEC_EVALUATION;
        case strHash("EXEC_NOISE_ESTIMATION"): return lbcrypto::ExecutionMode::EXEC_NOISE_ESTIMATION;
        default: throw std::runtime_error("ExecutionMode is not supported");
    }
}

[[nodiscard]] lbcrypto::DecryptionNoiseMode getDecryptionNoiseMode(const std::string_view decryptionNoiseMode)
{
    switch (strHash(decryptionNoiseMode))
    {
        case strHash("FIXED_NOISE_DECRYPT"): return lbcrypto::DecryptionNoiseMode::FIXED_NOISE_DECRYPT;
        case strHash("NOISE_FLOODING_DECRYPT"): return lbcrypto::DecryptionNoiseMode::NOISE_FLOODING_DECRYPT;
        default: throw std::runtime_error("DecryptionNoiseMode is not supported");
    }
}

[[nodiscard]] lbcrypto::COMPRESSION_LEVEL getCompressionLevel(const std::string_view compressionLevel)
{
    switch (strHash(compressionLevel))
    {
        case strHash("COMPACT"): return lbcrypto::COMPRESSION_LEVEL::COMPACT;
        case strHash("SLACK"): return lbcrypto::COMPRESSION_LEVEL::SLACK;
        default: throw std::runtime_error("COMPRESSION_LEVEL is not supported");
    }
}

} // namespace utils

} // namespace cli

