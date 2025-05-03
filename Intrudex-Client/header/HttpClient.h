#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <string>

class HttpClient {
public:
    explicit HttpClient(std::string serverUrl,
                        std::string userAgent = "Intrudex Client/1.0",
                        std::string contentType = "application/json",
                        bool useHttps = false);

    bool sendLog(const std::string& eventData) const;

private:
    std::string serverUrl;
    std::wstring wuserAgent;
    std::wstring wcontentType;
    bool forceHttps;
};

#endif // HTTPCLIENT_H
