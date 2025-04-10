#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>

namespace yama {
    std::wstring Utf8ToWideChar(const std::string& utf8str);
    std::string WideCharToUtf8(const std::wstring& widestr);
}

#endif // UTILS_HPP
