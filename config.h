#pragma once

#include "utils.h"

#include <nlohmann/json.hpp>

#include "openfhe/pke/cryptocontext-ser.h"
#include <openfhe/pke/gen-cryptocontext.h>
#include <openfhe/pke/scheme/bfvrns/gen-cryptocontext-bfvrns.h>
#include <openfhe/pke/scheme/bgvrns/gen-cryptocontext-bgvrns.h>
#include <openfhe/pke/scheme/ckksrns/gen-cryptocontext-ckksrns.h>

namespace cli
{

class ConfigProcessor final
{
private:
    nlohmann::json m_configJson;
    std::string m_outputCryptoObjectsDirectory;
    std::string m_outputConfigLocation;

    std::unordered_map<std::string_view,
        std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>> m_ccMap;
    std::unordered_map<std::string_view,
        std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>> m_publicKeyMap;
    std::unordered_map<std::string_view,
        std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>> m_privateKeyMap;

public:
    template <typename JsonType, typename StringType1, typename StringType2>
    explicit ConfigProcessor(
        JsonType&& configJson,
        StringType1&& outputCryptoObjectsDirectory,
        StringType2&& outputConfigLocation);

    ConfigProcessor(const ConfigProcessor&) = default;
    ConfigProcessor(ConfigProcessor&&) = default;
    ConfigProcessor& operator=(const ConfigProcessor&) = default;
    ConfigProcessor& operator=(ConfigProcessor&&) = default;

    template <typename JsonType>
    void setConfigJson(JsonType&& configJson);

    template <typename StringType1>
    void setOutputCryptoObjectsDirectory(StringType1&& outputCryptoObjectsDirectory);

    template <typename StringType2>
    void setOutputConfigLocation(StringType2&& outputConfigLocation);

    void generateOutputConfig();

private:
    template <typename KeyType>
    void generateKeyAndSerializeIfNotExist(
        const std::string_view keyName,
        nlohmann::json& keyContent);
    void generateCiphertextAndSerializeIfNotExist(
        const std::string& ciphertextName,
        nlohmann::json& ciphertextContent);
    void generateCCAndSerializeIfNotExist(
        const std::string_view ccName,
        nlohmann::json& ccContent);
    template <typename KeyGenFuncType, typename ...KeyGenFuncParamsTypes>
    void generateEvalKeyAndSerializeIfNotExist(
        const std::string& keyName,
        nlohmann::json& keyContent,
        KeyGenFuncType keyGenFunc,
        bool (*serializeFunc)(std::ostream&, const lbcrypto::SerType::SERBINARY&, std::string),
        KeyGenFuncParamsTypes&&... keyGenFuncParams);

    template <typename CryptoObjectType>
    void serialize(const std::string& filename,
        const std::shared_ptr<CryptoObjectType>& cryptoObject);
    void serialize(const std::string& filename,
        bool (*func)(std::ostream&, const lbcrypto::SerType::SERBINARY&, std::string)) const;
    template <typename CryptoObjectType>
    static void deserialize(const std::string& path,
        std::shared_ptr<CryptoObjectType>& cryptoObject);

    template <typename KeyType>
    [[nodiscard]] std::shared_ptr<KeyType> aquireKey(
        const std::string_view keyName);
    [[nodiscard]] std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> aquireCC(
        const std::string_view ccName);

    template <typename KeyType>
    void generateKeyPairAndSerialize(
        const std::string_view keyName,
        nlohmann::json& keyContent);

    [[nodiscard]] static lbcrypto::CryptoContext<lbcrypto::DCRTPoly> generateCC(
        const nlohmann::json& ccContent);
    template <typename SchemeType>
    [[nodiscard]] static lbcrypto::CCParams<SchemeType> getCCParams(
        const nlohmann::json& ccContent);

    template <typename KeyType>
    [[nodiscard]] inline auto& getKeyMap() noexcept;

    template <typename KeyType>
    [[nodiscard]] inline auto& getKeyFromKeyPair(
        lbcrypto::KeyPair<lbcrypto::DCRTPoly>& keyPair) noexcept;

    inline void updateSource(
        nlohmann::json& argContent,
        const std::string& filename);
};

template <typename JsonType, typename StringType1, typename StringType2>
ConfigProcessor::ConfigProcessor(
    JsonType&& configJson,
    StringType1&& outputCryptoObjectsDirectory,
    StringType2&& outputConfigLocation)
    : m_configJson(std::forward<JsonType>(configJson))
    , m_outputCryptoObjectsDirectory(std::forward<StringType1>(outputCryptoObjectsDirectory))
    , m_outputConfigLocation(std::forward<StringType2>(outputConfigLocation))
{ }

template <typename JsonType>
void ConfigProcessor::setConfigJson(JsonType&& configJson)
{
    m_configJson = std::forward<JsonType>(configJson);
}

template <typename StringType1>
void ConfigProcessor::setOutputCryptoObjectsDirectory(StringType1&& outputCryptoObjectsDirectory)
{
    m_outputCryptoObjectsDirectory = std::forward<StringType1>(outputCryptoObjectsDirectory);
}

template <typename StringType2>
void ConfigProcessor::setOutputConfigLocation(StringType2&& outputConfigLocation)
{
    m_outputConfigLocation = std::forward<StringType2>(outputConfigLocation);
}

void ConfigProcessor::generateOutputConfig()
{
    for (auto& [argName, argContent] : m_configJson.items())
    {
        switch (strHash(argContent["type"].get<std::string_view>()))
        {
            case strHash("cryptocontext"): generateCCAndSerializeIfNotExist(
                argName, argContent); break;
            case strHash("private_key"): generateKeyAndSerializeIfNotExist<
                lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(argName, argContent); break;
            case strHash("public_key"): generateKeyAndSerializeIfNotExist<
                lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>(argName, argContent); break;
            case strHash("ciphertext"): generateCiphertextAndSerializeIfNotExist(
                argName, argContent); break;
            case strHash("sum_key"): generateEvalKeyAndSerializeIfNotExist(
                argName, argContent,
                &lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::EvalSumKeyGen,
                &lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializeEvalSumKey<
                    lbcrypto::SerType::SERBINARY>,
                nullptr); break;
            case strHash("mult_key"): generateEvalKeyAndSerializeIfNotExist(
                argName, argContent,
                &lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::EvalMultKeyGen,
                &lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializeEvalMultKey<
                    lbcrypto::SerType::SERBINARY>); break;
            case strHash("rotation_key"): generateEvalKeyAndSerializeIfNotExist(
                argName, argContent,
                &lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::EvalRotateKeyGen,
                &lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializeEvalAutomorphismKey<
                    lbcrypto::SerType::SERBINARY>,
                argContent["indexes"].get<std::vector<int32_t>>(),
                nullptr); break;
            case strHash("i8"): [[fallthrough]];
            case strHash("i16"): [[fallthrough]];
            case strHash("i32"): [[fallthrough]];
            case strHash("i64"): [[fallthrough]];
            case strHash("u8"): [[fallthrough]];
            case strHash("u16"): [[fallthrough]];
            case strHash("u32"): [[fallthrough]];
            case strHash("u64"): [[fallthrough]];
            case strHash("f32"): [[fallthrough]];
            case strHash("f64"): [[fallthrough]];
            case strHash("bool"): break;
            default: throw std::runtime_error("Argument type is not supported");
        }
    }

    std::ofstream ofsOutputConfigJson(m_outputConfigLocation, std::ios::out);
    if (!ofsOutputConfigJson.is_open()) { throw std::runtime_error("Unable to open output config json"); }
    ofsOutputConfigJson << m_configJson.dump(4);
    ofsOutputConfigJson.close();

    m_ccMap.clear();
    m_privateKeyMap.clear();
    m_publicKeyMap.clear();
}

template <typename KeyType>
void ConfigProcessor::generateKeyAndSerializeIfNotExist(
    const std::string_view keyName, nlohmann::json& keyContent)
{
    if (getKeyMap<KeyType>().contains(keyName)) return;
    if (!keyContent["source"].get<std::string_view>().empty()) return;

    generateKeyPairAndSerialize<KeyType>(keyName, keyContent);
}

void ConfigProcessor::generateCiphertextAndSerializeIfNotExist(
    const std::string& ciphertextName, nlohmann::json& ciphertextContent)
{
    if (!ciphertextContent["source"].get<std::string_view>().empty()) return;

    std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> cc =
        aquireCC(ciphertextContent["cryptocontext"].get<std::string_view>());

    lbcrypto::Plaintext plaintext;
    switch (cc->getSchemeId())
    {
        case lbcrypto::SCHEME::CKKSRNS_SCHEME: plaintext = cc->MakeCKKSPackedPlaintext(
            ciphertextContent["plaintext_value"].get<std::vector<double>>()); break;
        case lbcrypto::SCHEME::BFVRNS_SCHEME: [[fallthrough]];
        case lbcrypto::SCHEME::BGVRNS_SCHEME: plaintext = cc->MakePackedPlaintext(
            ciphertextContent["plaintext_value"].get<std::vector<int64_t>>()); break;
        default: throw std::runtime_error("SCHEME type is not supported");
    }

    std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>> publicKey =
        aquireKey<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>(ciphertextContent["public_key"].get<std::string_view>());

    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext = cc->Encrypt(publicKey, plaintext);
    serialize<lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>>(ciphertextName, ciphertext);
    updateSource(ciphertextContent, ciphertextName);
}

void ConfigProcessor::generateCCAndSerializeIfNotExist(const std::string_view ccName, nlohmann::json& ccContent)
{
    if (m_ccMap.contains(ccName)) return;
    if (!ccContent["source"].get<std::string_view>().empty()) return;

    auto itCC = m_ccMap.emplace(ccName, generateCC(ccContent)).first;
    serialize<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>(std::string(itCC->first), itCC->second);
    updateSource(ccContent, std::string(itCC->first));
}

template <typename KeyGenFuncType, typename ...KeyGenFuncParamsTypes>
void ConfigProcessor::generateEvalKeyAndSerializeIfNotExist(
    const std::string& keyName,
    nlohmann::json& keyContent,
    KeyGenFuncType keyGenFunc,
    bool (*serializeFunc)(std::ostream&, const lbcrypto::SerType::SERBINARY&, std::string),
    KeyGenFuncParamsTypes&&... keyGenFuncParams)
{
    if (!keyContent["source"].get<std::string_view>().empty()) return;

    std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> cc =
        aquireCC(keyContent["cryptocontext"].get<std::string_view>());
    std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>> privateKey =
        aquireKey<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(keyContent["private_key"].get<std::string_view>());

    cc->Enable(lbcrypto::LEVELEDSHE);
    if constexpr (std::is_same_v<KeyGenFuncType,
        void (lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::*)(
            const std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>,
            const std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>)>)
    {
        cc->Enable(lbcrypto::ADVANCEDSHE);
    }
    std::invoke(keyGenFunc, cc, privateKey, std::forward<KeyGenFuncParamsTypes>(keyGenFuncParams)...);

    serialize(keyName, serializeFunc);
    updateSource(keyContent, keyName);
}

template <typename CryptoObjectType>
void ConfigProcessor::serialize(
    const std::string& filename, const std::shared_ptr<CryptoObjectType>& cryptoObject)
{
    if (!lbcrypto::Serial::SerializeToFile(
        m_outputCryptoObjectsDirectory + filename, cryptoObject, lbcrypto::SerType::BINARY))
    {
        throw std::runtime_error("Unable to serialize " + filename);
    }
}

void ConfigProcessor::serialize(
    const std::string& filename,
    bool (*func)(std::ostream&, const lbcrypto::SerType::SERBINARY&, std::string)) const
{
    std::ofstream ofs(m_outputCryptoObjectsDirectory + filename, std::ios::out | std::ios::binary);
    if (ofs.is_open())
    {
        if (!func(ofs, lbcrypto::SerType::BINARY, ""))
        {
            ofs.close();
            throw std::runtime_error("Unable to serialize " + filename);
        }
        ofs.close();
    }
    else
    {
        throw std::runtime_error(
            "Unable to open " + m_outputCryptoObjectsDirectory +
            filename + " file for writing serialization");
    }
}

template <typename CryptoObjectType>
void ConfigProcessor::deserialize(const std::string& path, std::shared_ptr<CryptoObjectType>& cryptoObject)
{
    if (!lbcrypto::Serial::DeserializeFromFile(path, cryptoObject, lbcrypto::SerType::BINARY))
    {
        throw std::runtime_error("Unable to deserialize " + path);
    }
}

template <typename KeyType>
[[nodiscard]] std::shared_ptr<KeyType> ConfigProcessor::aquireKey(const std::string_view keyName)
{
    auto& keyMap = getKeyMap<KeyType>();
    auto itKey = keyMap.find(keyName);
    if (itKey == keyMap.end())
    {
        if (m_configJson[keyName]["source"].get<std::string_view>().empty())
        {
            generateKeyPairAndSerialize<KeyType>(keyName, m_configJson[keyName]);
            itKey = keyMap.find(keyName);
        }
        else
        {
            std::shared_ptr<KeyType> key;
            static constexpr size_t mainPathStartingIndex = 8;
            deserialize<KeyType>(
                m_configJson[keyName]["source"].get_ref<const std::string&>().substr(mainPathStartingIndex), key);
            itKey = keyMap.emplace(keyName, std::move(key)).first;
        }
    }

    return itKey->second;
}

[[nodiscard]] std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> ConfigProcessor::aquireCC(
    const std::string_view ccName)
{
    auto itCC = m_ccMap.find(ccName);
    if (itCC == m_ccMap.end())
    {
        if (m_configJson[ccName]["source"].get<std::string_view>().empty())
        {
            itCC = m_ccMap.emplace(ccName, generateCC(m_configJson[ccName])).first;
            serialize<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>(std::string(itCC->first), itCC->second);
            updateSource(m_configJson[ccName], std::string(itCC->first));
        }
        else
        {
            std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> cc;
            static constexpr size_t mainPathStartingIndex = 8;
            deserialize<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>(
                m_configJson[ccName]["source"].get_ref<const std::string&>().substr(mainPathStartingIndex), cc);
            itCC = m_ccMap.emplace(ccName, std::move(cc)).first;
        }
    }

    return itCC->second;
}

template <typename KeyType>
void ConfigProcessor::generateKeyPairAndSerialize(const std::string_view keyName, nlohmann::json& keyContent)
{
    std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> cc =
        aquireCC(keyContent["cryptocontext"].get<std::string_view>());
    cc->Enable(lbcrypto::PKE);
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair = cc->KeyGen();
    const std::string& linkedKeyName
        = keyContent["linked_key_for_generation"].get_ref<const std::string&>();
    if (!linkedKeyName.empty())
    {
        if (!(m_configJson[linkedKeyName]["linked_key_for_generation"].get<std::string_view>() == keyName &&
            m_configJson[linkedKeyName]["source"].get<std::string_view>().empty()))
        {
            throw std::runtime_error("Incorrect linking between keys");
        }
        if constexpr (std::is_same_v<KeyType, lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>)
        {
            auto itKey = getKeyMap<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>().emplace(
                linkedKeyName, std::move(getKeyFromKeyPair<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>(keyPair))).first;
            serialize<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>(linkedKeyName, itKey->second);
        }
        else
        {
            auto itKey = getKeyMap<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>().emplace(
                linkedKeyName, std::move(getKeyFromKeyPair<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(keyPair))).first;
            serialize<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(linkedKeyName, itKey->second);
        }
        updateSource(m_configJson[linkedKeyName], linkedKeyName);
    }
    else
    {
        if constexpr (std::is_same_v<KeyType, lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>)
        {
            serialize<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>(std::string(keyName) + "." +
                m_configJson[linkedKeyName]["type"].get<std::string>(),
                getKeyFromKeyPair<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>(keyPair));
        }
        else
        {
            serialize<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(std::string(keyName) + "." +
                m_configJson[linkedKeyName]["type"].get<std::string>(),
                getKeyFromKeyPair<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(keyPair));
        }
    }
    auto itKey = getKeyMap<KeyType>().emplace(keyName, std::move(getKeyFromKeyPair<KeyType>(keyPair))).first;
    serialize<KeyType>(std::string(itKey->first), itKey->second);
    updateSource(keyContent, std::string(itKey->first));
}

[[nodiscard]] lbcrypto::CryptoContext<lbcrypto::DCRTPoly> ConfigProcessor::generateCC(const nlohmann::json& ccContent)
{
    switch (strHash(ccContent["scheme"].get<std::string_view>()))
    {
        case strHash("BFVRNS_SCHEME"): return lbcrypto::GenCryptoContext(
            getCCParams<lbcrypto::CryptoContextBFVRNS>(ccContent));
        case strHash("BGVRNS_SCHEME"): return lbcrypto::GenCryptoContext(
            getCCParams<lbcrypto::CryptoContextBGVRNS>(ccContent));
        case strHash("CKKSRNS_SCHEME"): return lbcrypto::GenCryptoContext(
            getCCParams<lbcrypto::CryptoContextCKKSRNS>(ccContent));
        default: throw std::runtime_error("Scheme type is not supported");
    }
}

template <typename SchemeType>
[[nodiscard]] lbcrypto::CCParams<SchemeType> ConfigProcessor::getCCParams(const nlohmann::json& ccContent)
{
    lbcrypto::CCParams<SchemeType> params;
    if (ccContent.contains("ptModulus")) {
        params.SetPlaintextModulus(ccContent["ptModulus"].get<uint64_t>()); }
    if (ccContent.contains("digitSize")) {
        params.SetDigitSize(ccContent["digitSize"].get<uint32_t>()); }
    if (ccContent.contains("standardDeviation")) {
        params.SetStandardDeviation(ccContent["standardDeviation"].get<float>()); }
    if (ccContent.contains("maxRelinSkDeg")) {
        params.SetMaxRelinSkDeg(ccContent["maxRelinSkDeg"].get<uint32_t>()); }
    if (ccContent.contains("firstModSize")) {
        params.SetFirstModSize(ccContent["firstModSize"].get<uint32_t>()); }
    if (ccContent.contains("scalingModSize")) {
        params.SetScalingModSize(ccContent["scalingModSize"].get<uint32_t>()); }
    if (ccContent.contains("batchSize")) {
        params.SetBatchSize(ccContent["batchSize"].get<uint32_t>()); }
    if (ccContent.contains("numLargeDigits")) {
        params.SetNumLargeDigits(ccContent["numLargeDigits"].get<uint32_t>()); }
    if (ccContent.contains("multiplicativeDepth")) {
        params.SetMultiplicativeDepth(ccContent["multiplicativeDepth"].get<uint32_t>()); }
    if (ccContent.contains("ringDim")) {
        params.SetRingDim(ccContent["ringDim"].get<uint32_t>()); }
    if (ccContent.contains("evalAddCount")) {
        params.SetEvalAddCount(ccContent["evalAddCount"].get<uint32_t>()); }
    if (ccContent.contains("keySwitchCount")) {
        params.SetKeySwitchCount(ccContent["keySwitchCount"].get<uint32_t>()); }
    if (ccContent.contains("PRENumHops")) {
        params.SetPRENumHops(ccContent["PRENumHops"].get<uint32_t>()); }
    if (ccContent.contains("noiseEstimate")) {
        params.SetNoiseEstimate(ccContent["noiseEstimate"].get<double>()); }
    if (ccContent.contains("desiredPrecision")) {
        params.SetDesiredPrecision(ccContent["desiredPrecision"].get<double>()); }
    if (ccContent.contains("statisticalSecurity")) {
        params.SetStatisticalSecurity(ccContent["statisticalSecurity"].get<uint32_t>()); }
    if (ccContent.contains("numAdversarialQueries")) {
        params.SetNumAdversarialQueries(ccContent["numAdversarialQueries"].get<uint32_t>()); }
    if (ccContent.contains("thresholdNumOfParties")) {
        params.SetThresholdNumOfParties(ccContent["thresholdNumOfParties"].get<uint32_t>()); }
    if (ccContent.contains("secretKeyDist")) {
        params.SetSecretKeyDist(getSecretKeyDist(ccContent["secretKeyDist"].get<std::string_view>())); }
    if (ccContent.contains("ksTech")) {
        params.SetKeySwitchTechnique(getKeySwitchTechnique(ccContent["ksTech"].get<std::string_view>())); }
    if (ccContent.contains("scalTech")) {
        params.SetScalingTechnique(getScalingTechnique(ccContent["scalTech"].get<std::string_view>())); }
    if (ccContent.contains("securityLevel")) {
        params.SetSecurityLevel(getSecurityLevel(ccContent["securityLevel"].get<std::string_view>())); }
    if (ccContent.contains("encryptionTechnique")) {
        params.SetEncryptionTechnique(
            getEncryptionTechnique(ccContent["encryptionTechnique"].get<std::string_view>())); }
    if (ccContent.contains("multiplicationTechnique")) {
        params.SetMultiplicationTechnique(
            getMultiplicationTechnique(ccContent["multiplicationTechnique"].get<std::string_view>())); }
    if (ccContent.contains("PREMode")) {
        params.SetPREMode(getProxyReEncryptionMode(ccContent["PREMode"].get<std::string_view>())); }
    if (ccContent.contains("multipartyMode")) {
        params.SetMultipartyMode(getMultipartyMode(ccContent["multipartyMode"].get<std::string_view>())); }
    if (ccContent.contains("executionMode")) {
        params.SetExecutionMode(getExecutionMode(ccContent["executionMode"].get<std::string_view>())); }
    if (ccContent.contains("decryptionNoiseMode")) {
        params.SetDecryptionNoiseMode(
            getDecryptionNoiseMode(ccContent["decryptionNoiseMode"].get<std::string_view>())); }
    if (ccContent.contains("interactiveBootCompressionLevel")) {
        params.SetInteractiveBootCompressionLevel(
            getCompressionLevel(ccContent["interactiveBootCompressionLevel"].get<std::string_view>())); }

    return params;
}

template <typename KeyType>
[[nodiscard]] inline auto& ConfigProcessor::getKeyMap() noexcept
{
    if constexpr (std::is_same_v<std::remove_cvref_t<KeyType>, lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>)
        return m_privateKeyMap;
    else
        return m_publicKeyMap;
}

template <typename KeyType>
[[nodiscard]] inline auto& ConfigProcessor::getKeyFromKeyPair(lbcrypto::KeyPair<lbcrypto::DCRTPoly>& keyPair) noexcept
{
    if constexpr (std::is_same_v<std::remove_cvref_t<KeyType>, lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>)
        return keyPair.secretKey;
    else
        return keyPair.publicKey;
}

inline void ConfigProcessor::updateSource(nlohmann::json& argContent, const std::string& filename)
{
    static const std::string path = "local://" + m_outputCryptoObjectsDirectory;
    argContent["source"] = path + filename;
}

} // namespace cli

