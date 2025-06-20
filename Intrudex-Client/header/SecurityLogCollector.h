#pragma once

#include <string>
#include <winevt.h>

#include "SecurityHttpSender.h"

class SecurityLogCollector {
public:
    SecurityLogCollector();
    ~SecurityLogCollector();

    bool start();
private:
    std::string apiUrl;
    std::wstring eventLogSource;
    std::wstring eventFilter;
    int sleepIntervalMs;
    std::string logLevel;

    SecurityHttpSender* httpSender;
    EVT_HANDLE subscriptionHandle = nullptr;

    void loadConfiguration();
    void handleEvent(const std::string& eventXml) const;
};