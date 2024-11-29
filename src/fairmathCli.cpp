#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>

#include "configProcessor.h"

namespace po = boost::program_options;

int main(int argc, char *argv[]) try
{
    po::options_description desc("Allowed options");
    desc.add_options()
    ("help", "produce help message")

    ("mode", po::value<std::string>(), "mode specifies cli working mode (generate or decrypt)")

    ("input_cfg", po::value<std::string>(), "input_cfg specifies input config location (mode: generate)")
    ("output_cfg", po::value<std::string>(), "output_cfg specifies output config location (mode: generate)")
    ("workdir", po::value<std::string>()->default_value("."), "workdir specifies the directory in which to generate crypto objects (mode: generate)")
    ("json_indent", po::value<int>()->default_value(-1), "json_indent specifies indent for output config (mode: generate)")

    ("cc", po::value<std::string>(), "cc specifies cryptocontext location (mode: decrypt)")
    ("key", po::value<std::string>(), "key specifies decryption key location (mode: decrypt)")
    ("slots", po::value<int>()->default_value(10), "slots specifies plaintext length (mode: decrypt)")
    ("output", po::value<std::string>(), "output specifies decrypted result location (mode: decrypt)")
    ("input", po::value<std::string>(), "input specifies input ciphertext location (mode: decrypt)");

    po::positional_options_description p;
    p.add("mode", 1);
    p.add("input", 1);

    po::variables_map variablesMap;
    const auto& parsed = po::command_line_parser(argc, argv).options(desc).positional(p).run();
    po::store(parsed, variablesMap);
    po::notify(variablesMap);

    if (variablesMap.count("help")) { std::cout << desc << '\n'; return EXIT_SUCCESS; }

    if (!variablesMap.count("mode")) { throw std::runtime_error("Mode is not specified"); }
    if (std::find_if(parsed.options.begin(), parsed.options.end(),
        [](const po::option& option) { return option.string_key == "mode"; })
        != parsed.options.begin())
    {
        throw std::runtime_error("Mode must be at the beginning");
    }

    const std::string& mode = variablesMap["mode"].as<const std::string&>();
    if (mode == "generate")
    {
        if (!variablesMap.count("input_cfg")) { throw std::runtime_error("Input config location is not specified"); }
        if (!variablesMap.count("output_cfg")) { throw std::runtime_error("Output config location is not specified"); }

        std::ifstream ifsInputConfigJson(variablesMap["input_cfg"].as<const std::string&>(), std::ios::in);
        if (!ifsInputConfigJson.is_open()) { throw std::runtime_error("Unable to open " + variablesMap["input_cfg"].as<const std::string&>()); }
        nlohmann::json configJson = nlohmann::json::parse(ifsInputConfigJson);
        ifsInputConfigJson.close();

        std::string outputCryptoObjectsDirectory = variablesMap["workdir"].as<std::string>();
        if (outputCryptoObjectsDirectory.back() != '/') { outputCryptoObjectsDirectory.push_back('/'); }

        cli::ConfigProcessor(
            std::move(configJson),
            std::move(outputCryptoObjectsDirectory),
            variablesMap["output_cfg"].as<std::string>(),
            variablesMap["json_indent"].as<int>()
        ).generateOutputConfig();
    }
    else if (mode == "decrypt")
    {
        if (!variablesMap.count("cc")) { throw std::runtime_error("Cryptocontext location is not specified"); }
        if (!variablesMap.count("key")) { throw std::runtime_error("Decryption key location is not specified"); }
        if (!variablesMap.count("output")) { throw std::runtime_error("Output decrypted result location is not specified"); }
        if (!variablesMap.count("input")) { throw std::runtime_error("Input ciphertext location is not specified"); }

        if (std::find_if(parsed.options.begin(), parsed.options.end(),
            [](const po::option& option) { return option.string_key == "input"; })
            != std::prev(parsed.options.end()))
        {
            throw std::runtime_error("Input must be at the end");
        }

        std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> cc;
        cli::utils::deserialize(variablesMap["cc"].as<const std::string&>(), cc);

        std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>> privateKey;
        cli::utils::deserialize(variablesMap["key"].as<const std::string&>(), privateKey);

        std::shared_ptr<lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>> ciphertext;
        cli::utils::deserialize(variablesMap["input"].as<const std::string&>(), ciphertext);

        std::shared_ptr<lbcrypto::PlaintextImpl> plaintext;
        cc->Decrypt(ciphertext, privateKey, &plaintext);

        if (dynamic_cast<const lbcrypto::StringEncoding*>(plaintext.get()))
        {
            if (std::find_if(parsed.options.begin(), parsed.options.end(),
                [](const po::option& option) { return option.string_key == "slots"; })
                != parsed.options.end())
            {
                throw std::runtime_error("Slots are unavailable for string encoding");
            }
        }
        else
        {
            plaintext->SetLength(variablesMap["slots"].as<int>());
        }

        std::ofstream ofsOutputDecryption(variablesMap["output"].as<const std::string&>(), std::ios::out);
        if (!ofsOutputDecryption.is_open()) { throw std::runtime_error("Unable to open" + variablesMap["output"].as<const std::string&>()); }
        ofsOutputDecryption << plaintext;
        ofsOutputDecryption.close();
    }
    else
    {
        throw std::runtime_error("Supported modes are: generate and decrypt");
    }

    return EXIT_SUCCESS;
}
catch (const po::error& ex)
{
    std::cerr << ex.what() << std::endl;
    return EXIT_FAILURE;
}
catch (const std::exception& ex)
{
    std::cerr << ex.what() << std::endl;
    return EXIT_FAILURE;
}
catch (...)
{
    std::cerr << "An unknown exception was thrown" << std::endl;
    return EXIT_FAILURE;
}

