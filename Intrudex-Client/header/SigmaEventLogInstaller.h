#pragma once

#include <string>

namespace SigmaEventLogInstaller {
    // Registers the IntrudexSigma event source and message file in the registry
    bool installEventSource(const std::wstring& sourceName, const std::wstring& messageFilePath);
    // Optionally, provide a cleanup/uninstall function
    bool uninstallEventSource(const std::wstring& sourceName);
} 