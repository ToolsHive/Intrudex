#pragma once

#include <string>

class SysmonManager {
public:
    static bool install(const std::string& sysmonPath, const std::string& configPath);
    static void uninstall();
    static void printManifest();
    static void printCurrentConfig();
};
