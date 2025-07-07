#include <iostream>
#include <Windows.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <shellapi.h>
#include <psapi.h>
#include <filesystem>
#include <iomanip>
#include <tlhelp32.h>

#include "../header/utils.h"
#include "../header/sysmon_manager.h"
#include "../header/SysmonCollector.h"
#include "../header/ApplicationLogCollector.h"
#include "../header/SecurityLogCollector.h"
#include "../header/SystemLogCollector.h"

#include "../includes/json.hpp"
#include "../includes/cxxopts.hpp"

using json = nlohmann::json;

// Global flags
bool g_verbose = false;
bool g_background = false;
bool g_foreground = false;

#define vout if (g_verbose && !(g_background && !g_foreground)) std::cout
#define eout if (!(g_background && !g_foreground)) std::cerr

// Admin Check
bool isRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// UAC Relaunch
bool relaunchAsAdmin(int argc, char* argv[]) {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;

    std::wstring args;
    for (int i = 1; i < argc; ++i) {
        int len = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
        std::wstring warg(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &warg[0], len);
        args += L"\"" + warg + L"\" ";
    }

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;

    return ShellExecuteExW(&sei);
}

// Banner
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

// Get config JSON
json loadClientConfig(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) throw std::runtime_error("Failed to open client_config.json");
    json config;
    file >> config;
    return config;
}

// Get Executable Dir
std::string getExecutableDirectory() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    std::string path(buffer);
    return path.substr(0, path.find_last_of("\\"));
}

// Check Sysmon
bool isSysmonInstalled() {
    return system("cd /d C:\\Windows\\System32 && Sysmon64.exe -h >nul 2>&1") == 0;
}

// Helper: Get process uptime in seconds
double getProcessUptime() {
    FILETIME create, exit, kernel, user;
    if (GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user)) {
        ULARGE_INTEGER c;
        c.LowPart = create.dwLowDateTime;
        c.HighPart = create.dwHighDateTime;
        std::time_t start = (c.QuadPart - 116444736000000000ULL) / 10000000ULL;
        std::time_t now = std::time(nullptr);
        return difftime(now, start);
    }
    return 0.0;
}

// Helper: Get process RAM usage in MB
size_t getProcessMemoryMB() {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);
    }
    return 0;
}

// Helper: Get total system RAM in MB
size_t getTotalSystemMemoryMB() {
    MEMORYSTATUSEX statex{}; statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        return statex.ullTotalPhys / (1024 * 1024);
    }
    return 0;
}

// Helper: Get CPU usage (simple average since process start)
double getProcessCpuUsage() {
    static ULARGE_INTEGER lastKernel{} , lastUser{}, lastTime{};
    FILETIME sysIdle, sysKernel, sysUser, procCreate, procExit, procKernel, procUser;
    GetSystemTimes(&sysIdle, &sysKernel, &sysUser);
    GetProcessTimes(GetCurrentProcess(), &procCreate, &procExit, &procKernel, &procUser);

    ULARGE_INTEGER k, u, t;
    k.LowPart = procKernel.dwLowDateTime; k.HighPart = procKernel.dwHighDateTime;
    u.LowPart = procUser.dwLowDateTime;   u.HighPart = procUser.dwHighDateTime;
    t.LowPart = sysKernel.dwLowDateTime;  t.HighPart = sysKernel.dwHighDateTime;

    static bool first = true;
    double cpu = 0.0;
    if (!first) {
        const ULONGLONG deltaProc = (k.QuadPart + u.QuadPart) - (lastKernel.QuadPart + lastUser.QuadPart);
        const ULONGLONG deltaTime = t.QuadPart - lastTime.QuadPart;
        if (deltaTime > 0)
            cpu = 100.0 * deltaProc / deltaTime;
    }
    lastKernel = k; lastUser = u; lastTime = t; first = false;
    return cpu;
}

// Helper: Get thread count for current process
DWORD getProcessThreadCount() {
    DWORD pid = GetCurrentProcessId();
    DWORD threadCount = 0;
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32{}; te32.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid)
                    ++threadCount;
            } while (Thread32Next(hThreadSnap, &te32));
        }
        CloseHandle(hThreadSnap);
    }
    return threadCount;
}

// Helper: Get process info string
std::string getProcessInfo() {
    DWORD pid = GetCurrentProcessId();
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::ostringstream oss;
    oss << "PID: " << pid << ", Executable: " << exePath;
    return oss.str();
}

// Helper: Print runtime stats in a beautiful, clear format (no tables)
void printRuntimeStatsPretty() {
    double cpu = getProcessCpuUsage();
    size_t ramMB = getProcessMemoryMB();
    size_t totalRAM = getTotalSystemMemoryMB();
    double uptimeSec = getProcessUptime();
    int days = static_cast<int>(uptimeSec) / (24 * 3600);
    int hours = (static_cast<int>(uptimeSec) % (24 * 3600)) / 3600;
    int minutes = (static_cast<int>(uptimeSec) % 3600) / 60;
    int seconds = static_cast<int>(uptimeSec) % 60;
    DWORD threadCount = getProcessThreadCount();
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    DWORD coreCount = sysinfo.dwNumberOfProcessors;
    DWORD pid = GetCurrentProcessId();
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    std::cout << "\n------------------- Runtime Stats -------------------\n";
    std::cout << "CPU Usage      : " << std::fixed << std::setprecision(2) << cpu << " %\n";
    std::cout << "RAM Usage      : " << ramMB << " MB / " << totalRAM << " MB\n";
    std::cout << "Core Count     : " << coreCount << "\n";
    std::cout << "Uptime         : "
              << days << "d "
              << std::setw(2) << std::setfill('0') << hours << "h "
              << std::setw(2) << std::setfill('0') << minutes << "m "
              << std::setw(2) << std::setfill('0') << seconds << "s\n";
    std::cout << "Thread Count   : " << threadCount << "\n";
    std::cout << "Process        : PID " << pid << " | " << exePath << "\n";
    std::cout << "-----------------------------------------------------\n";
}

// Main
int main(int argc, char* argv[]) {
    registerSignalHandlers();

    cxxopts::Options options("Intrudex_Client", "Sigma-Powered IPS/IDS Client");
    options.add_options()
        ("h,help", "Show help")
        ("v,verbose", "Verbose mode")
        ("version", "Show version info")
        ("background", "Run in background")
        ("foreground", "Force foreground output")
        ("timeout", "Exit after N seconds", cxxopts::value<int>())
        ("config", "Custom config path", cxxopts::value<std::string>())
        ("reinstall-sysmon", "Reinstall Sysmon")
        ("custom-sysmon", "Reinstall Sysmon with config", cxxopts::value<std::string>())
        ("sysmon-manifest", "Print Sysmon manifest")
        ("sysmon-config", "Print Sysmon running config")
        ("sysmon-uninstall", "Uninstall Sysmon")
        ("force", "Force install Sysmon")
        ("dry-run", "Simulate without running collectors")
        ("status", "Show current status")
        ("check-health", "Perform health check")
        ("disable-collector", "Disable collectors", cxxopts::value<std::string>())
    ;

    // Load config early to get default flags if needed
    std::string configPath = getExecutableDirectory() + "\\config\\client_config.json";
    json config;
    try {
        config = loadClientConfig(configPath);
    } catch (...) {
        // Ignore if not found, will error later if needed
    }

    // Default flag logic: use foreground/background if no args, or from config
    std::string defaultFlag = "background";
    if (config.contains("default_flag")) {
        defaultFlag = config["default_flag"].get<std::string>();
    }

    // Parse arguments (always parse, even if argc == 1, to allow default behavior)
    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    } catch (const std::exception& e) {
        printBanner();
        std::cerr << "[Error] " << e.what() << "\n" << options.help() << "\n";
        return 1;
    }

    // Set flags based on args or default
    g_verbose = result.count("verbose") > 0;
    g_background = result.count("background") > 0;
    g_foreground = result.count("foreground") > 0;

    // If no arguments, use default_flag from config or fallback to foreground/background
    if (argc == 1) {
        if (defaultFlag == "background") {
            g_background = true;
            g_foreground = false;
        } else {
            g_foreground = true;
            g_background = false;
        }
    }

    // --- UAC Elevation Logic ---
    // If not running as admin, always relaunch with UAC prompt (even on double-click)
    if (!isRunningAsAdmin()) {
        vout << "[Intrudex] Admin privileges required. Relaunching with UAC...\n";
        if (relaunchAsAdmin(argc, argv)) {
            return 0; // Relaunch initiated, original process exits
        } else {
            eout << "[Error] Failed to elevate. Exiting.\n";
            return 1;
        }
    }

    // --- Background logic ---
    // If running as admin and in background mode, detach and free terminal
    if (g_background && !g_foreground) {
        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        std::string cmdLine = GetCommandLineA();
        // Remove --background from command line for child (if present)
        size_t pos = cmdLine.find("--background");
        if (pos != std::string::npos) cmdLine.erase(pos, std::string("--background").length());

        BOOL success = CreateProcessA(
            nullptr,
            &cmdLine[0],
            nullptr,
            nullptr,
            FALSE,
            DETACHED_PROCESS | CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        if (success) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 0; // Parent exits, child runs in background
        } else {
            std::cerr << "[Error] Failed to background process. Error: " << GetLastError() << "\n";
            return 1;
        }
    }

    if (result.count("help")) {
        printBanner();
        std::cout << options.help() << "\n";
        return 0;
    }

    if (result.count("version")) {
        printBanner();
        std::cout << "Intrudex Client Agent v1.0.0\n";
        return 0;
    }

    int timeout = result.count("timeout") ? result["timeout"].as<int>() : 0;

    std::set<std::string> disabled;
    if (result.count("disable-collector")) {
        std::stringstream ss(result["disable-collector"].as<std::string>());
        std::string item;
        while (getline(ss, item, ',')) disabled.insert(item);
    }

    if (result.count("sysmon-manifest")) {
        printBanner();
        SysmonManager::printManifest();
        return 0;
    }

    if (result.count("sysmon-config")) {
        printBanner();
        SysmonManager::printCurrentConfig();
        return 0;
    }

    if (result.count("sysmon-uninstall")) {
        printBanner();
        SysmonManager::uninstall();
        return 0;
    }

    try {
        json config = loadClientConfig(configPath);
        std::string exeDir = getExecutableDirectory();
        std::string sysmonExe = exeDir + "\\" + config["sysmon_exe_path"].get<std::string>();
        std::string sysmonCfg = exeDir + "\\" + config["sysmon_config_path"].get<std::string>();

        // Normalize path slashes for Windows
        std::replace(sysmonExe.begin(), sysmonExe.end(), '/', '\\');
        std::replace(sysmonCfg.begin(), sysmonCfg.end(), '/', '\\');

        // Validate sysmonExe and sysmonCfg paths before attempting install
        if (!std::filesystem::exists(sysmonExe)) {
            std::cerr << "[Error] Sysmon executable not found at: " << sysmonExe << "\n";
            return 1;
        }
        if (!std::filesystem::exists(sysmonCfg)) {
            std::cerr << "[Error] Sysmon config not found at: " << sysmonCfg << "\n";
            return 1;
        }

        if (result.count("check-health")) {
            printBanner();
            std::cout << "[HealthCheck] Config File: " << (std::filesystem::exists(configPath) ? "[OK] Found" : "[FAIL] Missing") << "\n";
            std::cout << "[HealthCheck] Sysmon: " << (isSysmonInstalled() ? "[OK] Installed" : "[FAIL] Missing") << "\n";
            std::cout << "[HealthCheck] Log Dir: " << (std::filesystem::exists(exeDir + "\\logs") ? "[OK] Exists" : "[FAIL] Missing") << "\n";
            return 0;
        }

        if (result.count("status")) {
            printBanner();
            std::cout << "[Status] Config: " << configPath << "\n";
            std::cout << "[Status] Sysmon: " << (isSysmonInstalled() ? "[OK] Installed" : "[FAIL] Not Installed") << "\n";
            for (const std::string name : {"sysmon", "application", "security", "system"})
                std::cout << "[Status] Collector: " << name << ": " << (disabled.count(name) ? "Disabled" : "Enabled") << "\n";
            printRuntimeStatsPretty();
            return 0;
        }

        if (result.count("dry-run")) {
            printBanner();
            std::cout << "[DryRun] Loaded config from: " << configPath << "\n";
            for (const auto& [k, v] : config.items()) std::cout << "  - " << k << ": " << v << "\n";
            printRuntimeStatsPretty();
            return 0;
        }

        if (result.count("reinstall-sysmon") || result.count("custom-sysmon")) {
            std::string cfg = result.count("custom-sysmon")
                ? result["custom-sysmon"].as<std::string>()
                : sysmonCfg;

            SysmonManager::uninstall();
            if (SysmonManager::install(sysmonExe, cfg)) {
                std::cout << "[SysmonManager] Installed.\n";
                return 0;
            } else {
                std::cerr << "[Error] Sysmon install failed.\n";
                return 1;
            }
        }

        if (!isSysmonInstalled() || result.count("force")) {
            if (!SysmonManager::install(sysmonExe, sysmonCfg)) {
                std::cerr << "[Error] Failed to install Sysmon.\n";
                return 1;
            }
        }

        printBanner();

        std::vector<std::thread> threads;

        if (!disabled.count("sysmon")) {
            threads.emplace_back([] {
                {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[Sysmon] Starting...\n";
                }
                SysmonCollector c;
                if (!c.start()) {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cerr << "[Sysmon] Failed to start.\n";
                } else {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[Sysmon] Collector stopped.\n";
                }
            });
        }

        if (!disabled.count("application")) {
            threads.emplace_back([] {
                {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[Application] Starting...\n";
                }
                ApplicationLogCollector c;
                if (!c.start()) {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cerr << "[Application] Failed to start.\n";
                } else {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[Application] Collector stopped.\n";
                }
            });
        }

        if (!disabled.count("security")) {
            threads.emplace_back([] {
                {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[Security] Starting...\n";
                }
                SecurityLogCollector c;
                if (!c.start()) {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cerr << "[Security] Failed to start.\n";
                } else {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[Security] Collector stopped.\n";
                }
            });
        }

        if (!disabled.count("system")) {
            threads.emplace_back([] {
                {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[System] Starting...\n";
                }
                SystemLogCollector c;
                if (!c.start()) {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cerr << "[System] Failed to start.\n";
                } else {
                    std::lock_guard<std::mutex> lock(log_print_mutex);
                    std::cout << "[System] Collector stopped.\n";
                }
            });
        }

        if (timeout > 0) {
            std::thread([=]() {
                std::this_thread::sleep_for(std::chrono::seconds(timeout));
                std::cout << "[Timeout] Auto exiting.\n";
                cleanupResources();
                exit(0);
            }).detach();
        }

        for (auto& t : threads) t.join();

    } catch (const std::exception& e) {
        std::cerr << "\n[Exception] " << e.what() << "\n";
        return 1;
    }

    cleanupResources();
    return 0;
}
