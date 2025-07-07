#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include "../header/sysmon_manager.h"

// Helper to run a command in a specific working directory
static int runCommandInDir(const std::string& command, const std::string& workDir) {
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    // Duplicate the command string because CreateProcessA modifies it
    std::string cmd = command;
    BOOL success = CreateProcessA(
        nullptr,
        cmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &si,
        &pi
    );
    if (!success) {
        std::cerr << "[SysmonManager] CreateProcessA failed. Error: " << GetLastError() << std::endl;
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
}

bool SysmonManager::install(const std::string& sysmonPath, const std::string& configPath) {
    // Debug output for troubleshooting
    std::cout << "[SysmonManager] Attempting install with:\n";
    std::cout << "  Sysmon exe: " << sysmonPath << "\n";
    std::cout << "  Config xml: " << configPath << "\n";
    std::cout << "  Sysmon exe exists: " << (std::filesystem::exists(sysmonPath) ? "yes" : "no") << "\n";
    std::cout << "  Config xml exists: " << (std::filesystem::exists(configPath) ? "yes" : "no") << "\n";

    if (!std::filesystem::exists(sysmonPath)) {
        std::cerr << "[SysmonManager] Sysmon executable not found: " << sysmonPath << std::endl;
        return false;
    }
    if (!std::filesystem::exists(configPath)) {
        std::cerr << "[SysmonManager] Sysmon config not found: " << configPath << std::endl;
        return false;
    }

    // Get directory of sysmonPath
    std::filesystem::path sysmonExePath(sysmonPath);
    std::string sysmonDir = sysmonExePath.parent_path().string();

    // Build command
    std::string installCommand = "\"" + sysmonPath + "\" -accepteula -i \"" + configPath + "\"";
    std::cout << "[SysmonManager] Running command: " << installCommand << std::endl;

    int result = runCommandInDir(installCommand, sysmonDir);

    if (result == 0) {
        std::cout << "[SysmonManager] Sysmon installed successfully." << std::endl;
        return true;
    }

    std::cerr << "[SysmonManager] Failed to install Sysmon." << std::endl;
    return false;
}

void SysmonManager::uninstall() {
    system("sc stop Sysmon64");
    const std::string uninstallCommand = "Sysmon64.exe -u";
    std::cout << "[SysmonManager] Uninstalling Sysmon..." << std::endl;
    int result = system(uninstallCommand.c_str());

    if (result == 0) {
        std::cout << "[SysmonManager] Sysmon uninstalled successfully." << std::endl;
    } else {
        std::cerr << "[SysmonManager] Failed to uninstall Sysmon." << std::endl;
    }
}

void SysmonManager::printManifest() {
    std::cout << "[SysmonManager] Printing Sysmon manifest..." << std::endl;
    system("Sysmon64.exe -m");
}

void SysmonManager::printCurrentConfig() {
    std::cout << "[SysmonManager] Printing current Sysmon config..." << std::endl;
    system("Sysmon64.exe -c");
}
