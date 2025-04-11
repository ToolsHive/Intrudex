#include "../header/sysmon_manager.h"
#include <cstdlib>
#include <iostream>

bool SysmonManager::installSysmon(const std::string& sysmonPath, const std::string& configPath) {
    // Command to install Sysmon with configuration
    std::string installCommand = sysmonPath + " -accepteula -i " + configPath;

    // Execute the command

    if (const int result = system(installCommand.c_str()); result == 0) {
        std::cout << "Sysmon installed successfully." << std::endl;
        return true;
    } else {
        std::cout << "Failed to install Sysmon." << std::endl;
        return false;
    }
}


