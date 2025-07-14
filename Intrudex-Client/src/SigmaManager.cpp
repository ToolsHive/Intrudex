#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <atomic>
#include <thread>
#include <mutex>
#include <filesystem>
#include <unordered_set>

#include "../header/SigmaManager.h"
#include "../includes/json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

extern bool g_verbose;

SigmaManager::SigmaManager(const std::string& configPath, const std::string& rulesDir)
    : rulesDirectory(rulesDir), configFilePath(configPath) {
    loadConfig();
}

void SigmaManager::loadConfig() {
    std::ifstream inFile(configFilePath);
    if (!inFile.is_open()) throw std::runtime_error("Failed to open config file.");

    json configJson;
    inFile >> configJson;

    apiBaseUrl = configJson["api_base_url"];
    for (auto& [key, val] : configJson["headers"].items()) {
        headers[key] = val;
    }
}

std::vector<std::string> SigmaManager::getLocalRuleNames() const {
    std::vector<std::string> names;
    if (!fs::exists(rulesDirectory)) fs::create_directories(rulesDirectory);

    // Recursively iterate through all directories
    for (const auto& entry : fs::recursive_directory_iterator(rulesDirectory)) {
        if (entry.path().extension() == ".yml") {
            // Use the relative path from the rules directory to match with remote path structure
            fs::path relativePath = fs::relative(entry.path(), rulesDirectory);
            names.push_back(relativePath.string());
        }
    }
    return names;
}

bool SigmaManager::fileExists(const std::string& path) {
    return fs::exists(path);
}

std::string SigmaManager::httpGet(const std::string& urlPath) {
    HINTERNET hInternet = InternetOpenA("SigmaClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) throw std::runtime_error("InternetOpen failed");

    URL_COMPONENTSA urlComp = {};
    char host[256], path[1024];
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = sizeof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path);
    urlComp.dwSchemeLength = -1;

    std::string fullUrl = apiBaseUrl + urlPath;
    if (!InternetCrackUrlA(fullUrl.c_str(), 0, 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        throw std::runtime_error("URL parsing failed");
    }

    HINTERNET hConnect = InternetConnectA(hInternet, host, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) throw std::runtime_error("InternetConnect failed");

    const char* acceptTypes[] = { "*/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path, NULL, NULL, acceptTypes, INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) throw std::runtime_error("HttpOpenRequest failed");

    std::ostringstream headersStream;
    for (auto& [key, val] : headers) {
        headersStream << key << ": " << val << "\r\n";
    }

    std::string headerStr = headersStream.str();
    if (!HttpSendRequestA(hRequest, headerStr.c_str(), headerStr.size(), NULL, 0)) {
        throw std::runtime_error("HttpSendRequest failed");
    }

    std::stringstream result;
    char buffer[4096];
    DWORD bytesRead;

    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead) {
        result.write(buffer, bytesRead);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return result.str();
}

// Helper to recursively flatten the tree
void SigmaManager::flattenRuleTree(const nlohmann::json& node, std::vector<std::unordered_map<std::string, std::string>>& out) {
    if (node.contains("type") && node["type"] == "file" && node.contains("name") && node.contains("path")) {
        out.push_back({
            {"name", node["name"].get<std::string>()},
            {"path", node["path"].get<std::string>()}
        });
    }
    if (node.contains("children") && node["children"].is_array()) {
        for (const auto& child : node["children"]) {
            flattenRuleTree(child, out);
        }
    }
}

std::vector<std::unordered_map<std::string, std::string>> SigmaManager::fetchRemoteRules() {
    std::string response = httpGet("/rules");

    try {
        auto rulesJson = json::parse(response);
        if (!rulesJson.contains("tree") || !rulesJson["tree"].is_array()) {
            std::cerr << "[Error] /rules response missing 'tree' array: " << response << std::endl;
            throw std::runtime_error("Expected 'tree' array in /rules endpoint");
        }
        std::vector<std::unordered_map<std::string, std::string>> result;
        for (const auto& node : rulesJson["tree"]) {
            flattenRuleTree(node, result);
        }
        return result;
    } catch (const std::exception& e) {
        std::cerr << "[Error] Failed to parse JSON response: " << e.what() << std::endl;
        throw;
    }
}

void SigmaManager::downloadRule(const std::string& rulePath, const std::string& fileName) {
    try {
        std::string fullPath = "/rule/" + rulePath;
        std::replace(fullPath.begin(), fullPath.end(), '\\', '/'); // Normalize slashes

        // Get the rule data - it's a JSON with a 'content' field containing the YAML
        std::string response = httpGet(fullPath);

        try {
            // Parse the JSON response
            auto ruleJson = json::parse(response);

            // Extract the YAML content from the 'content' field
            if (!ruleJson.contains("content")) {
                throw std::runtime_error("Rule response missing 'content' field");
            }

            std::string yamlContent = ruleJson["content"].get<std::string>();

            // Extract directory structure from the path
            std::string dirPath = rulePath;
            std::replace(dirPath.begin(), dirPath.end(), '\\', '/'); // Normalize slashes

            // Remove the filename from the path to get directory structure
            size_t lastSlash = dirPath.find_last_of('/');
            if (lastSlash != std::string::npos) {
                dirPath = dirPath.substr(0, lastSlash);
            } else {
                dirPath = ""; // No subdirectory
            }

            // Create full directory structure
            std::string fullDirPath = rulesDirectory + "/" + dirPath;
            if (!dirPath.empty() && !fs::exists(fullDirPath)) {
                fs::create_directories(fullDirPath);
            }

            // Write the YAML content to the file with the proper path
            std::string fullFilePath = rulesDirectory + "/" +
                (dirPath.empty() ? "" : dirPath + "/") + fileName;

            std::ofstream outFile(fullFilePath);
            outFile << yamlContent;
            std::cout << "[+] Downloaded: " << (dirPath.empty() ? "" : dirPath + "/") << fileName << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[-] Failed to parse rule JSON: " << e.what() << std::endl;
            throw;
        }
    } catch (const std::exception& e) {
        std::cerr << "[-] Failed to download rule: " << fileName << " - " << e.what() << std::endl;
        throw; // Rethrow to count as failed in updateRules
    }
}

void SigmaManager::updateRules() {
    std::cout << "[SigmaManager] Checking for rule updates..." << std::endl;

    // Get existing rules - convert to unordered_set for O(1) lookups
    auto localRules = getLocalRuleNames();
    std::unordered_set<std::string> localRuleSet(localRules.begin(), localRules.end());
    std::cout << "[SigmaManager] Found " << localRuleSet.size() << " existing rules locally" << std::endl;

    // Fetch remote rules
    auto remoteRules = fetchRemoteRules();
    std::cout << "[SigmaManager] Found " << remoteRules.size() << " rules on server" << std::endl;

    // Track statistics
    std::atomic<int> skipped = 0;
    std::atomic<int> downloaded = 0;
    std::atomic<int> failed = 0;

    // Use a thread pool for parallel downloads (limit to hardware concurrency)
    const unsigned int maxThreads = std::thread::hardware_concurrency();
    const unsigned int numThreads = std::min(maxThreads,
        static_cast<unsigned int>(remoteRules.size() > 16 ? 16 : remoteRules.size()));

    if (numThreads > 1) {
        std::vector<std::thread> threads;
        std::mutex ruleMutex;
        size_t ruleIndex = 0;

        // Launch worker threads
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.emplace_back([&]() {
                while (true) {
                    // Get next rule to process
                    std::unordered_map<std::string, std::string> rule;
                    {
                        std::lock_guard<std::mutex> lock(ruleMutex);
                        if (ruleIndex >= remoteRules.size()) {
                            break;  // No more rules to process
                        }
                        rule = remoteRules[ruleIndex++];
                    }

                    std::string name = rule.at("name");
                    std::string path = rule.at("path");

                    // Extract directory structure from the path
                    std::string dirPath = path;
                    std::replace(dirPath.begin(), dirPath.end(), '\\', '/'); // Normalize slashes

                    // Remove the filename from the path to get directory structure
                    size_t lastSlash = dirPath.find_last_of('/');
                    if (lastSlash != std::string::npos) {
                        dirPath = dirPath.substr(0, lastSlash);
                    } else {
                        dirPath = ""; // No subdirectory
                    }

                    // Check if rule exists locally already
                    std::string relativeRulePath = (dirPath.empty() ? "" : dirPath + "/") + name;
                    if (localRuleSet.find(relativeRulePath) != localRuleSet.end()) {
                        // Rule exists, skip download
                        skipped++;
                        if (g_verbose) {
                            std::lock_guard<std::mutex> lock(ruleMutex);
                            std::cout << "[SigmaManager] Skipped (exists): " << relativeRulePath << std::endl;
                        }
                        continue;
                    }

                    // Download missing rule
                    try {
                        downloadRule(path, name);
                        downloaded++;
                    } catch (const std::exception&) {
                        // Error already printed in downloadRule
                        failed++;
                    }
                }
            });
        }

        // Wait for all threads to complete
        for (auto& t : threads) {
            t.join();
        }
    } else {
        // Single-threaded fallback for small rule sets
        for (const auto& rule : remoteRules) {
            std::string name = rule.at("name");
            std::string path = rule.at("path");

            // Extract directory structure from the path
            std::string dirPath = path;
            std::replace(dirPath.begin(), dirPath.end(), '\\', '/'); // Normalize slashes

            // Remove the filename from the path to get directory structure
            size_t lastSlash = dirPath.find_last_of('/');
            if (lastSlash != std::string::npos) {
                dirPath = dirPath.substr(0, lastSlash);
            } else {
                dirPath = ""; // No subdirectory
            }

            // Check if rule exists locally already
            std::string relativeRulePath = (dirPath.empty() ? "" : dirPath + "/") + name;
            if (localRuleSet.find(relativeRulePath) != localRuleSet.end()) {
                // Rule exists, skip download
                skipped++;
                if (g_verbose) std::cout << "[SigmaManager] Skipped (exists): " << relativeRulePath << std::endl;
                continue;
            }

            // Download missing rule
            try {
                downloadRule(path, name);
                downloaded++;
            } catch (const std::exception&) {
                // Error already printed in downloadRule
                failed++;
            }
        }
    }

    std::cout << "[SigmaManager] Rule update complete. "
              << "Downloaded: " << downloaded << ", "
              << "Skipped: " << skipped << ", "
              << "Failed: " << failed << std::endl;
}