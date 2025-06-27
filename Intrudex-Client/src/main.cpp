#include <iostream>
#include <Windows.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <mutex>

#include "../header/utils.h"

#include "../header/sysmon_manager.h"
#include "../header/SysmonCollector.h"
#include "../header/ApplicationLogCollector.h"
#include "../header/SecurityLogCollector.h"
#include "../header/SystemLogCollector.h"

#include "../includes/json.hpp"

using json = nlohmann::json;

void printBanner() {
    std::cout << R"(
   ___       _                  _
  |_ _|_ __ | |_ _ __ _   _  __| | _____  __
   | || '_ \| __| '__| | | |/ _` |/ _ \ \/ /
   | || | | | |_| |  | |_| | (_| |  __/>  <
  |___|_| |_|\__|_|   \__,_|\__,_|\___/_/\_\

 Intrudex Client Agent - Powered by Sigma Rules
===========================================================
)" << std::endl;
}

// Load client config from JSON file
json loadClientConfig(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open client_config.json");
    }

    json config;
    file >> config;
    return config;
}

// Get directory where this executable is located
std::string getExecutableDirectory() {
    char buffer[MAX_PATH];
    if (GetModuleFileNameA(nullptr, buffer, MAX_PATH) == 0) {
        throw std::runtime_error("Failed to get executable path.");
    }
    const std::string exePath(buffer);
    const size_t pos = exePath.find_last_of("\\");
    return exePath.substr(0, pos);
}

// Check if Sysmon is installed
bool isSysmonInstalled() {
    const std::string command = "cd /d C:\\Windows\\System32 && Sysmon64.exe -h > nul 2>&1";
    return system(command.c_str()) == 0;
}

int main() {
    registerSignalHandlers();
    printBanner();

    try {
        const std::string exeDir = getExecutableDirectory();
        const std::string configFilePath = exeDir + "\\config\\client_config.json";
        json config = loadClientConfig(configFilePath);

        const std::string sysmonPath = exeDir + "\\" + config["sysmon_exe_path"].get<std::string>();
        const std::string configPath = exeDir + "\\" + config["sysmon_config_path"].get<std::string>();

        std::cout << "\n[System] Checking Sysmon status...\n" << std::endl;

        if (isSysmonInstalled()) {
            std::cout << "[System] Sysmon is already installed.\n" << std::endl;
        } else {
            std::cout << "[System] Sysmon not found. Attempting installation...\n" << std::endl;
            if (SysmonManager::install(sysmonPath, configPath)) {
                std::cout << "[SysmonManager] Sysmon installed successfully.\n" << std::endl;
            } else {
                std::cerr << "[Error] Failed to install Sysmon.\n" << std::endl;
                return 1;
            }
        }

        std::cout << "===========================================================\n" << std::endl;

        std::cout << "[Sysmon] Starting Sysmon Collector...\n" << std::endl;
        SysmonCollector sysmonCollector;
        std::thread sysmonThread([&]() {
            if (sysmonCollector.start()) {
                std::cout << "[Sysmon] Collector started.\n" << std::endl;
                while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                std::cerr << "[Sysmon] Failed to start collector.\n" << std::endl;
            }
        });

        std::cout << "[Application] Starting Application Log Collector...\n" << std::endl;
        ApplicationLogCollector appLogCollector;
        std::thread appLogThread([&]() {
            if (appLogCollector.start()) {
                std::cout << "[Application] Collector started.\n" << std::endl;
                while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                std::cerr << "[Application] Failed to start collector.\n" << std::endl;
            }
        });

        std::cout << "[Security] Starting Security Log Collector...\n" << std::endl;
        SecurityLogCollector securityLogCollector;
        std::thread securityLogThread([&]() {
            if (securityLogCollector.start()) {
                std::cout << "[Security] Collector started.\n" << std::endl;
                while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                std::cerr << "[Security] Failed to start collector.\n" << std::endl;
            }
        });

        std::cout << "[System] Starting System Log Collector...\n" << std::endl;
        SystemLogCollector systemLogCollector;
        std::thread systemLogThread([&]() {
            if (systemLogCollector.start()) {
                std::cout << "[System] Collector started.\n" << std::endl;
                while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                std::cerr << "[System] Failed to start collector.\n" << std::endl;
            }
        });

        sysmonThread.join();
        appLogThread.join();
        securityLogThread.join();
        systemLogThread.join();

    } catch (const std::exception& e) {
        std::cerr << "\n[Error] Exception: " << e.what() << "\n" << std::endl;
        cleanupResources(); // Ensure cleanup before exiting
        return 1;
    }

    cleanupResources(); // Final cleanup before exiting
    return 0;
}