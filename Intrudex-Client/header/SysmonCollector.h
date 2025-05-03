#pragma once

#include <string>
#include "HttpClient.h"

class SysmonCollector {
public:
    SysmonCollector();
    ~SysmonCollector();

    bool start();

private:
    std::string serverUrl;
    std::wstring eventLogSource;
    std::wstring eventFilter;
    int sleepIntervalMs;
    std::string logLevel;
    bool sendEvents;

    HttpClient* httpClient;

    void loadConfiguration();

    void handleEvent(const std::string& eventXml) const;
};