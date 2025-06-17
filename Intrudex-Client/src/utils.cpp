#include "../header/utils.h"
#include "../includes/pugixml.hpp"

#include <iostream>
#include <sstream>
#include <locale>
#include <windows.h>
#include <signal.h>
#include <string>

// Define the global mutex
std::mutex log_print_mutex;

std::wstring utf8_to_wstring(const std::string& str) {
    static int consecutiveErrors = 0; // Track consecutive errors

    if (str.empty()) {
        return L"";
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (size_needed <= 0) {
        std::cerr << "[Warning] Failed to calculate buffer size for UTF-8 to wide string conversion.\n";
        consecutiveErrors++;
        if (consecutiveErrors >= 3) {
            std::cerr << "[Error] Too many consecutive errors. Exiting...\n";
            cleanupResources();
            exit(1);
        }
        return L""; // Skip the problematic log
    }

    std::wstring result(size_needed, L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size_needed) == 0) {
        std::cerr << "[Warning] Failed to convert UTF-8 string to wide string.\n";
        consecutiveErrors++;
        if (consecutiveErrors >= 3) {
            std::cerr << "[Error] Too many consecutive errors. Exiting...\n";
            cleanupResources();
            exit(1);
        }
        return L""; // Skip the problematic log
    }

    result.resize(size_needed - 1); // Remove the null terminator
    consecutiveErrors = 0; // Reset error count on successful conversion
    return result;
}

std::string prettyPrintXml(const std::string& xml) {
    pugi::xml_document doc;
    if (!doc.load_string(xml.c_str())) {
        return xml; // Return original XML if it fails to parse
    }

    std::stringstream ss;
    doc.save(ss, "    ", pugi::format_indent); // Indented output
    return ss.str();
}

// Global pointers for cleanup (can be extended as needed)
void* globalResource1 = nullptr;
void* globalResource2 = nullptr;

void cleanupResources() {
    if (globalResource1) {
        delete static_cast<int*>(globalResource1); // Example cleanup
        globalResource1 = nullptr;
    }

    if (globalResource2) {
        delete static_cast<int*>(globalResource2); // Example cleanup
        globalResource2 = nullptr;
    }

    std::cout << "[System] Cleanup complete.\n";
}

void signalHandler(int signal) {
    std::cout << "\n[System] Signal received: " << signal << ". Cleaning up resources...\n";
    cleanupResources();
    exit(signal);
}

void registerSignalHandlers() {
    signal(SIGINT, signalHandler);  // Handle Ctrl + C
    signal(SIGTERM, signalHandler); // Handle termination signals
    signal(SIGABRT, signalHandler); // Handle abort signals
}