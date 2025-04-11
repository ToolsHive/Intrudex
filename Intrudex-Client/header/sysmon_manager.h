#ifndef SYSMON_MANAGER_H
#define SYSMON_MANAGER_H

#include <string>

class SysmonManager {
public:
    static bool installSysmon(const std::string& sysmonPath, const std::string& configPath);
};

#endif // SYSMON_MANAGER_H
