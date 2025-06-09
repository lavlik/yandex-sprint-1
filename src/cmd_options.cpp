#include "cmd_options.h"
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>
namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Show help message")("command,c", po::value<std::string>(), "Command type")(
        "input,i", po::value<std::string>(), "Input file path")(
        "output,o", po::value<std::string>(), "Output file path")("password,p", po::value<std::string>(), "Password");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        desc_.print(std::cout);
        return true;
    }

    if (vm.count("command")) {
        const auto value = vm["command"].as<std::string>();
        if (!commandMapping_.contains(value)) {
            throw std::runtime_error("Unknown command: " + value);
        }
        command_ = commandMapping_.at(value);
    } else {
        throw std::runtime_error("Command is mandatory!");
    }

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    } else {
        throw std::runtime_error("Input is mandatory!");
    }

    const bool hasOutput = vm.count("output");
    const bool hasPassword = vm.count("password");
    if (GetCommand() != COMMAND_TYPE::CHECKSUM) {
        if (hasOutput) {
            outputFile_ = vm["output"].as<std::string>();
        } else {
            throw std::runtime_error("Output is mandatory!");
        }
        if (hasPassword) {
            password_ = vm["password"].as<std::string>();
        } else {
            throw std::runtime_error("Password is mandatory!");
        }
    } else if (hasOutput || hasPassword) {
        throw std::runtime_error("No need  options!");
    }

    return false;
}

}  // namespace CryptoGuard
