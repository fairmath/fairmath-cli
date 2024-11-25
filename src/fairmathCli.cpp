#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>

#include "configProcessor.h"

namespace po = boost::program_options;

int main(int argc, char *argv[]) try
{
    po::options_description desc("Allowed parameters");
    desc.add_options()
    ("help,h", "produce help message")

    ("working_mode", po::value<std::string>(), "set working_mode (config_processing or ciphertext_decryption)")

    ("input_config_location", po::value<std::string>(), "set input_config_location (config_processing)")
    ("output_crypto_objects_directory", po::value<std::string>(), "set output_crypto_objects_directory (config_processing)")
    ("output_config_location", po::value<std::string>(), "set output_config_location (config_processing)")
    ("output_config_json_indent", po::value<std::string>(), "set output_config_json_indent (config_processing)")

    ("output_decryption_location", po::value<std::string>(), "set output_decryption_location (ciphertext_decryption)")
    ("decryption_cryptocontext_location", po::value<std::string>(), "set decryption_cryptocontext_location (ciphertext_decryption)")
    ("ciphertext_location", po::value<std::string>(), "set ciphertext_location (ciphertext_decryption)")
    ("decryption_key_location", po::value<std::string>(), "set decryption_key_location (ciphertext_decryption)")
    ("plaintext_length", po::value<std::string>(), "set plaintext_length (ciphertext_decryption)");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) { std::cout << desc << '\n'; return EXIT_SUCCESS; }
    if (!vm.count("working_mode")) { throw std::runtime_error("working_mode is not specified"); }
    const std::string& workingMode = vm["working_mode"].as<const std::string&>();

    if (workingMode == "config_processing")
    {
        // config_processing
        if (vm.count("output_decryption_location") || vm.count("decryption_cryptocontext_location") ||
            vm.count("ciphertext_location") || vm.count("decryption_key_location") || vm.count("plaintext_length"))
        {
            throw std::runtime_error("ciphertext_decryption working_mode argument(s) were provided for config_processing working_mode");
        }
        if (!vm.count("input_config_location")) { throw std::runtime_error("input_config_location is not specified"); }
        if (!vm.count("output_crypto_objects_directory")) { throw std::runtime_error("output_crypto_objects_directory is not specified"); }
        if (!vm.count("output_config_location")) { throw std::runtime_error("output_config_location is not specified"); }
        if (!vm.count("output_config_json_indent")) { throw std::runtime_error("output_config_json_indent is not specified"); }

        std::ifstream ifsInputConfigJson(vm["input_config_location"].as<const std::string&>(), std::ios::in);
        if (!ifsInputConfigJson.is_open()) { throw std::runtime_error("Unable to open " + vm["input_config_location"].as<const std::string&>()); }
        nlohmann::json configJson = nlohmann::json::parse(ifsInputConfigJson);
        ifsInputConfigJson.close();

        std::string outputCryptoObjectsDirectory = vm["output_crypto_objects_directory"].as<std::string>();
        if (outputCryptoObjectsDirectory.back() != '/') { outputCryptoObjectsDirectory.push_back('/'); }

        cli::ConfigProcessor(
            std::move(configJson),
            std::move(outputCryptoObjectsDirectory),
            vm["output_config_location"].as<std::string>(),
            std::stoi(vm["output_config_json_indent"].as<const std::string&>())
        ).generateOutputConfig();
    }
    else if (workingMode == "ciphertext_decryption")
    {
        // ciphertext_decryption
        if (vm.count("input_config_location") || vm.count("output_crypto_objects_directory") ||
            vm.count("output_config_location") || vm.count("output_config_json_indent"))
        {
            throw std::runtime_error("config_processing working_mode argument(s) were provided for ciphertext_decryption working_mode");
        }

        if (!vm.count("output_decryption_location")) { throw std::runtime_error("output_decryption_location is not specified"); }
        if (!vm.count("decryption_cryptocontext_location")) { throw std::runtime_error("decryption_cryptocontext_location is not specified"); }
        if (!vm.count("ciphertext_location")) { throw std::runtime_error("ciphertext_location is not specified"); }
        if (!vm.count("decryption_key_location")) { throw std::runtime_error("decryption_key_location is not specified"); }

        std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>> cc;
        cli::utils::deserialize(vm["decryption_cryptocontext_location"].as<const std::string&>(), cc);

        std::shared_ptr<lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>> ciphertext;
        cli::utils::deserialize(vm["ciphertext_location"].as<const std::string&>(), ciphertext);

        std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>> privateKey;
        cli::utils::deserialize(vm["decryption_key_location"].as<const std::string&>(), privateKey);

        std::shared_ptr<lbcrypto::PlaintextImpl> plaintext;
        cc->Decrypt(ciphertext, privateKey, &plaintext);

        if (vm.count("plaintext_length")) { plaintext->SetLength(std::stoull(vm["plaintext_length"].as<const std::string&>())); }

        std::ofstream ofsOutputDecryption(vm["output_decryption_location"].as<const std::string&>(), std::ios::out);
        if (!ofsOutputDecryption.is_open()) { throw std::runtime_error("Unable to open" + vm["output_decryption_location"].as<const std::string&>()); }
        ofsOutputDecryption << plaintext;
        ofsOutputDecryption.close();
    }
    else
    {
        throw std::runtime_error("Supported working_modes are: config_processing and ciphertext_decryption");
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

