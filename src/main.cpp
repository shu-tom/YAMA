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

extern "C" YAMA_API BSTR __cdecl MemoryScan(const char* ruleString) {
    try {
        int verbosity = 0; // warnレベル
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
        strOutputPath = std::string(yama::WideCharToUtf8(lpwcAbsPath));
        LOGTRACE("Output path {}", strOutputPath);

        auto context = std::make_unique<yama::ScannerContext>();

        if (context->canRecordEventlog) { 
            LOGTRACE("Enabled Eventlog logging.");
            EventRegisterYAMA(); 
        }

        std::vector<DWORD> vPids = yama::ListPid();
        LOGINFO("Yama will scan {} process(es).", vPids.size());

        auto scanner = std::make_unique<yama::YamaScanner>(&vPids);
        {
            yama::YaraManager manager;
            if (!manager.YrAddRuleFromString(ruleString)) {
                LOGERROR("Failed to add rule from string.");
                return nullptr;
            }
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

        auto reporter = std::make_unique<yama::Reporter>(context.get(), scanner->suspiciousProcessList);
        std::unique_ptr<std::string> strReport;
        if (isJson) {
            strReport.reset(reporter->GenerateJsonReport());
        } else {
            strReport.reset(reporter->GenerateTextReport());
        }

        std::wstring wReport(strReport->begin(), strReport->end());
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