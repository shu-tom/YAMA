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
#include "utils.hpp"

#ifndef YAMA_API
#ifdef _WIN32
	#define YAMA_API __declspec(dllexport)
#else
	#define YAMA_API
#endif
#endif

const char* version = "1.0";

extern "C" YAMA_API BSTR __stdcall MemoryScan(const char* ruleString) {
    if (ruleString == nullptr) {
        LOGERROR("MemoryScan received a null ruleString.");
        return nullptr;
    }
    
    try {
        int verbosity = 0;
        std::string strOutputPath = "./";
        bool isJson = false;

        spdlog::set_pattern("%^%-9l%$: %v");
        spdlog::set_level(spdlog::level::warn);

        wchar_t lpwcAbsPath[MAX_PATH] = {0};
        DWORD dwResult = GetFullPathNameW(yama::StdStringToWideChar(strOutputPath), MAX_PATH, lpwcAbsPath, NULL);
        if (dwResult == 0) {
            LOGERROR("Failed to expand relative path. Set valid path.");
            return nullptr;
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
        
        yama::YaraManager manager;
        if (!manager.YrAddRuleFromString(rule.c_str())) {
            LOGERROR("Failed to add rule from string.");
            return nullptr;
        }

        scanner->ScanPidList();

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
                return nullptr;
            }
        }

        std::wstring wReport = yama::Utf8ToWideChar(*strReport);
        
        if (context->canRecordEventlog) { 
            EventWriteProcessStopped(); 
            EventUnregisterYAMA();
        }

        return SysAllocString(wReport.c_str());
    }
    catch (const std::exception& ex) {
        LOGERROR("Exception caught: {}", ex.what());
        return nullptr;
    }
    catch (...) {
        LOGERROR("Unknown exception caught.");
        return nullptr;
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