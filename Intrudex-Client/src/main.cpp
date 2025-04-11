#include "../header/sysmon_manager.h"
#include <iostream>
#include <Windows.h>

bool isSysmonInstalled() {
    // Command to check Sysmon installation status, change directory first, then run Sysmon64.exe
    const std::string command = "cd /d C:\\Windows\\System32 && Sysmon64.exe -h > nul 2>&1";

    // Execute the command and capture the result
    const DWORD result = system(command.c_str());

    // If result is 0, Sysmon is installed
    return result == 0;
}

int main() {
    // Get the path of the executable
    char buffer[MAX_PATH];
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    const std::string exePath(buffer);

    // Find the directory of the executable
    const size_t pos = exePath.find_last_of("\\");
    const std::string exeDir = exePath.substr(0, pos);

    // Construct absolute paths for Sysmon and config
    const std::string sysmonPath = exeDir + "\\Sysmon64.exe";
    const std::string configPath = exeDir + "\\sysmonconfig-export.xml";

    if (isSysmonInstalled()) {
        std::cout << "Sysmon is already installed." << std::endl;
    } else {
        // Use these paths for installation
        if (SysmonManager::installSysmon(sysmonPath, configPath)) {
            std::cout << "Installation successful." << std::endl;
        } else {
            std::cout << "Installation failed." << std::endl;
        }
    }
    // DEBUG: Wait for user input to exit (For Debugging)
    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
