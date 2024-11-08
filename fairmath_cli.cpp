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
    ("input_config", po::value<std::string>(), "set input config json location")
    ("output_crypto_objects", po::value<std::string>(), "set absolute path to output directory of crypto objects")
    ("output_config", po::value<std::string>(), "set output config json location")
    ("output_config_json_indent", po::value<std::string>()->default_value("-1")->implicit_value("-1"), "set output config json indent (default: -1)");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) { std::cout << desc << '\n'; return EXIT_SUCCESS; }
    if (!vm.count("input_config")) { throw std::runtime_error("Input config file location is not specified"); }
    if (!vm.count("output_crypto_objects")) { throw std::runtime_error("Output crypto objects directory not specified"); }
    if (!vm.count("output_config")) { throw std::runtime_error("Output config file location is not specified"); }

    std::ifstream ifsInputConfigJson(vm["input_config"].as<const std::string&>(), std::ios::in);
    if (!ifsInputConfigJson.is_open()) { throw std::runtime_error("Unable to open input config json"); }
    nlohmann::json configJson = nlohmann::json::parse(ifsInputConfigJson);
    ifsInputConfigJson.close();

    std::string outputCryptoObjectsDirectory = vm["output_crypto_objects"].as<std::string>();
    if (outputCryptoObjectsDirectory.back() != '/') { outputCryptoObjectsDirectory.push_back('/'); }

    cli::ConfigProcessor(
        std::move(configJson),
        std::move(outputCryptoObjectsDirectory),
        vm["output_config"].as<std::string>(),
        std::stoi(vm["output_config_json_indent"].as<const std::string&>())).generateOutputConfig();

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

