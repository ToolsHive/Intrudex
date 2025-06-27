#pragma once

#include <string>

class SystemHttpSender {
public:
    SystemHttpSender(const std::string& url);
    bool sendLog(const std::string& logData);
    static std::string getHostname();

private:
    std::string apiUrl;
    static std::wstring utf8_to_wstring(const std::string& str);
};