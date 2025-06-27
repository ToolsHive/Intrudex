#pragma once

#include <string>
#include <winevt.h> // Include Windows Event Log API

#include "HttpClient.h"

class SysmonCollector {
public:
    SysmonCollector();
    ~SysmonCollector();

    bool start();
    void printStatus(const std::string& msg) const;

private:
    std::string serverUrl;
    std::wstring eventLogSource;
    std::wstring eventFilter;
    int sleepIntervalMs;
    std::string logLevel;
    bool sendEvents;

    HttpClient* httpClient;
    EVT_HANDLE subscriptionHandle = nullptr;

    void loadConfiguration();
    void handleEvent(const std::string& eventXml) const;
};