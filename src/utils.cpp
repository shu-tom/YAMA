#include "utils.hpp"
#include <windows.h>

namespace yama {

std::wstring Utf8ToWideChar(const std::string& utf8str) {
    if (utf8str.empty()) {
        return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), static_cast<int>(utf8str.size()), NULL, 0);
    if (size_needed <= 0) {
        return std::wstring();
    }
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), static_cast<int>(utf8str.size()), &wstr[0], size_needed);
    return wstr;
}

std::string WideCharToUtf8(const std::wstring& widestr) {
    if (widestr.empty()) {
        return std::string();
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, widestr.c_str(), static_cast<int>(widestr.size()), NULL, 0, NULL, NULL);
    if (size_needed <= 0) {
        return std::string();
    }
    std::string utf8str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, widestr.c_str(), static_cast<int>(widestr.size()), &utf8str[0], size_needed, NULL, NULL);
    return utf8str;
}

} // namespace yama
