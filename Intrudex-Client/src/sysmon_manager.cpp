#include <cstdlib>
#include <iostream>

#include "../header/sysmon_manager.h"


bool SysmonManager::install(const std::string& sysmonPath, const std::string& configPath) {
    const std::string installCommand = sysmonPath + " -accepteula -i " + configPath;

    if (const int result = system(installCommand.c_str()); result == 0) {
        std::cout << "[SysmonManager] Sysmon installed successfully." << std::endl;
        return true;
    } else {
        std::cerr << "[SysmonManager] Failed to install Sysmon." << std::endl;
        return false;
    }
}