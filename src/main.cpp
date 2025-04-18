#define NOMINMAX
#include <argparse/argparse.hpp>
#include <windows.h>
#include <comutil.h>
#pragma comment(lib, "comsuppw.lib")

#include "../rsrc/resources.h"
#include "common.h"
#include "memory.hpp"
#include "pid.h"
#include "process.hpp"
#include "rc4.hpp"
#include "resource.h"
#include "reporter.hpp"
#include "scanner_context.hpp"
#include "thread.hpp"
#include "yaramanager.hpp"
#include "yamascanner.hpp"

#ifndef YAMA_API
#ifdef _WIN32
	#define YAMA_API __declspec(dllexport)
#else
	#define YAMA_API
#endif
#endif

const char* version = "1.0";

// エクスポート関数の呼び出し規約を明確に指定
extern "C" YAMA_API int __stdcall MemoryScan(const char* ruleString, const char** result) {
    // ポインタと入力の検証
    if (result == nullptr) {
        LOGERROR("Result pointer is null");
        return -1;
    }
    
    *result = nullptr; // 初期化
    
    if (ruleString == nullptr) {
        LOGERROR("Rule string is null");
        char* pszReturn = (char*)::CoTaskMemAlloc(256);
        if (pszReturn) {
            strcpy_s(pszReturn, 256, "Error: Rule string is null");
            *result = pszReturn;
        }
        return -2;
    }

    try {
        // デフォルト値を設定
        int verbosity = 0;
        std::string strOutputPath = "./";
        bool isJson = false;

        spdlog::set_pattern("%^%-9l%$: %v");
        spdlog::set_level(spdlog::level::trace);

        wchar_t lpwcAbsPath[MAX_PATH] = {0};
        DWORD dwResult = GetFullPathNameW(yama::StdStringToWideChar(strOutputPath), MAX_PATH, lpwcAbsPath, NULL);
        if (dwResult == 0) {
            LOGERROR("Failed to expand relative path. Set valid path.");
        }
        if (!yama::PathExistsW(lpwcAbsPath)) {
            LOGWARN("Output path does not exist: {}", yama::WideCharToUtf8(lpwcAbsPath));
            GetCurrentDirectoryW(MAX_PATH, lpwcAbsPath);
        }
        strOutputPath = yama::WideCharToUtf8(lpwcAbsPath);

        auto context = std::make_unique<yama::ScannerContext>();

        if (context->canRecordEventlog) { 
            LOGTRACE("Enabled Eventlog logging.");
            EventRegisterYAMA(); 
        }

        std::vector<DWORD> vPids = yama::ListPid();
        LOGINFO("Yama will scan {} process(es).", vPids.size());

        auto scanner = std::make_unique<yama::YamaScanner>(&vPids);
        
        // ルールの追加
        yama::YaraManager manager;
        if (!manager.YrAddRuleFromString(ruleString)) {
            LOGERROR("Failed to add rule from string.");
            char* pszReturn = (char*)::CoTaskMemAlloc(256);
            if (pszReturn) {
                strcpy_s(pszReturn, 256, "Error: Failed to add YARA rule");
                *result = pszReturn;
            }
            return 0;
        }

        // プロセススキャン - 例外をキャッチ
        try {
            scanner->ScanPidList();
        }
        catch (const std::exception& ex) {
            LOGERROR("Exception during scanning: {}", ex.what());
            char* pszReturn = (char*)::CoTaskMemAlloc(256);
            if (pszReturn) {
                sprintf_s(pszReturn, 256, "Error during scanning: %s", ex.what());
                *result = pszReturn;
            }
            return 0;
        }

        LOGINFO("Suspicious Processes Count: {}", scanner->suspiciousProcessList->size());

        if (context->canRecordEventlog) {
            if (scanner->suspiciousProcessList->empty()) {
                EventWriteNoDetection();
            } else {
                EventWriteDetectsMalware();
            }
        }

        std::unique_ptr<std::string> strReport;
        auto reporter = std::make_unique<yama::Reporter>(context.get(), scanner->suspiciousProcessList);
        if (scanner->suspiciousProcessList->empty()) {
            strReport = std::make_unique<std::string>("No suspicious processes detected.");
        } else {
            if (isJson) {
                strReport.reset(reporter->GenerateJsonReport());
            } else {
                strReport.reset(reporter->GenerateTextReport());
            }

            if (!strReport) {
                LOGERROR("Failed to generate report.");
            }
        }

        // 結果の生成
        size_t len = strReport->size() + 1;
        char* pszReturn = (char*)::CoTaskMemAlloc(len);
        if (pszReturn) {
            memcpy_s(pszReturn, len, strReport->c_str(), len);
            *result = pszReturn;
        }
        else {
            LOGERROR("Failed to allocate memory for result");
            return -3;
        }

        if (context->canRecordEventlog) { 
            EventWriteProcessStopped(); 
            EventUnregisterYAMA();
        }

        return 1;
    }
    catch (const std::exception& ex) {
        LOGERROR("Exception caught: {}", ex.what());
        char* pszReturn = (char*)::CoTaskMemAlloc(256);
        if (pszReturn) {
            sprintf_s(pszReturn, 256, "Error: %s", ex.what());
            *result = pszReturn;
        }
        return 0;
    }
    catch (...) {
        LOGERROR("Unknown exception caught.");
        char* pszReturn = (char*)::CoTaskMemAlloc(256);
        if (pszReturn) {
            strcpy_s(pszReturn, 256, "Error: Unknown exception");
            *result = pszReturn;
        }
        return 0;
    }
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
#endif