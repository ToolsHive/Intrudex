#pragma once

#include <string>
#include <winevt.h>
#include <vector>
#include <unordered_map>

#include "SigmaManager.h"
#include "SystemHttpSender.h"

class SigmaLogCollector {
public:
    SigmaLogCollector(const std::string& sigmaConfigPath, const std::string& sigmaRulesDir);
    ~SigmaLogCollector();

    bool start();
    void printStatus(const std::string& msg) const;

private:
    std::string apiUrl;
    std::wstring eventLogSource;
    std::wstring eventFilter;
    int sleepIntervalMs;
    std::string logLevel;
    std::string customLogName;

    SigmaManager* sigmaManager;
    SystemHttpSender* httpSender;
    EVT_HANDLE subscriptionHandle = nullptr;

    std::vector<std::unordered_map<std::string, std::string>> sigmaRules;

    void loadConfiguration();
    void loadSigmaRules();
    void handleEvent(const std::string& eventXml) const;
    bool matchesSigmaRule(const std::string& eventXml) const;
    void writeToCustomEventLog(const std::string& eventXml) const;
    void registerCustomEventLog() const;
    void showWindowsNotification(const std::string& title, const std::string& message) const;
}; 