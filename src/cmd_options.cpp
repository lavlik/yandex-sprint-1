#include "cmd_options.h"
#include <print>
#include <iostream>
#include <stdexcept>
#include <string>
namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Show help message")
    ("command,c",po::value<std::string>(), "Command type")
    ("input,i", po::value<std::string>(), "Input file path")
    ("output,o", po::value<std::string>(), "Output file path")
    ("password,p", po::value<std::string>(), "Password");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        desc_.print(std::cout);
        return true;
    }

    if (vm.count("command")) {
        const auto value = vm["command"].as<std::string>();
        if(!commandMapping_.contains(value)){
            throw std::runtime_error("Unknown command: " + value);
        }
        command_ = commandMapping_.at(value);
    }
    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }
    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }
    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }

    po::notify(vm);

    return false;
}

}  // namespace CryptoGuard
