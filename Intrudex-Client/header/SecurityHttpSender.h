#pragma once

#include <string>

class SecurityHttpSender {
public:
    SecurityHttpSender(const std::string& url);
    bool sendLog(const std::string& logData);
    bool sendSecurityLog(const std::string& logData); // Remove 'const'
    static std::string getHostname();

private:
    std::string apiUrl;
    static std::wstring utf8_to_wstring(const std::string& str);
};