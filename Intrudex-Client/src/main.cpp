#include <iostream>
#include <Windows.h>
#include <thread>
#include <chrono>

#include "../header/sysmon_manager.h"
#include "../header/SysmonCollector.h"


bool isSysmonInstalled() {
    const std::string command = "cd /d C:\\Windows\\System32 && Sysmon64.exe -h > nul 2>&1";
    return system(command.c_str()) == 0;
}

std::string getExecutableDirectory() {
    char buffer[MAX_PATH];
    if (GetModuleFileNameA(nullptr, buffer, MAX_PATH) == 0) {
        throw std::runtime_error("Failed to get executable path.");
    }
    const std::string exePath(buffer);
    const size_t pos = exePath.find_last_of("\\");
    return exePath.substr(0, pos);
}

int main() {
    try {
        const std::string exeDir = getExecutableDirectory();
        const std::string sysmonPath = exeDir + "\\assets\\Sysmon64.exe";
        const std::string configPath = exeDir + "\\config\\sysmonconfig-export.xml";

        if (isSysmonInstalled()) {
            std::cout << "[Main] Sysmon is already installed." << std::endl;
        } else {
            if (SysmonManager::install(sysmonPath, configPath)) {
                std::cout << "[Main] Sysmon installed successfully." << std::endl;
            } else {
                std::cerr << "[Main] Failed to install Sysmon." << std::endl;
                return 1;
            }
        }

        SysmonCollector collector;
        if (collector.start()) {
            std::wcout << L"[Main] SysmonCollector started. Press Ctrl+C to exit." << std::endl;
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            std::wcerr << L"[Main] Failed to start SysmonCollector." << std::endl;
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "[Main] Exception: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[Main] Unknown error occurred." << std::endl;
        return 1;
    }

    return 0;
}