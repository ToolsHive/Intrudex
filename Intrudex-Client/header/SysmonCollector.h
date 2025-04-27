#pragma once

#include <string>
#include "HttpClient.h"

class SysmonCollector {
public:
    SysmonCollector();
    ~SysmonCollector();

    bool start();

private:
    HttpClient* httpClient;
    std::string serverUrl;

    void loadConfiguration();
    void handleEvent(const std::string& eventXml) const;
};