#define NOMINMAX
#include <argparse/argparse.hpp>
#include <windows.h>

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

extern "C" YAMA_API int MemoryScan(const char* ruleString, char** result) {
    int verbosity = 0; // warn レベルに相当
    std::string strOutputPath = "./";
    bool isJson = false;
    
    // init logger settings
    spdlog::set_pattern("%^%-9l%$: %v");  // ...existing code...
  
    // Set log verbosity level（引数による変更は行わない）
    spdlog::set_level(spdlog::level::warn);

    // Convert output path to absolute path
    wchar_t* lpwcAbsPath = new wchar_t[MAX_PATH]();
    DWORD dwResult = GetFullPathNameW(yama::StdStringToWideChar(strOutputPath), MAX_PATH, lpwcAbsPath, NULL);
    if (dwResult == 0) {
        LOGERROR("Failed to expand relative path. Set valid path.")
        return 1;
    }
    if (!yama::PathExistsW(lpwcAbsPath)) {
        LOGWARN("Output path does not exists:  {}", yama::WideCharToUtf8(lpwcAbsPath));
        LOGWARN("Set output path to current directory.");
        GetCurrentDirectoryW(MAX_PATH, lpwcAbsPath);
    }
    strOutputPath = std::string(yama::WideCharToUtf8(lpwcAbsPath));
    LOGTRACE("Output path {}", strOutputPath);
    
    // Set scanner context
    yama::ScannerContext* context = new yama::ScannerContext();

    // 登録処理のみ実施
    if (context->canRecordEventlog) { 
        LOGTRACE("Enabled Eventlog logging.");
        EventRegisterYAMA(); 
    }

    // 全プロセスをスキャン
    std::vector<DWORD> vPids = yama::ListPid();
    LOGINFO("Yama will scan {} process(es).", vPids.size());

    // Initialize YamaScanner
    yama::YamaScanner *scanner = new yama::YamaScanner(&vPids);
    {
        yama::YaraManager manager;
        if (!manager.YrAddRuleFromString(ruleString)) {
            LOGERROR("Failed to add rule from string.");
            return 1;
        }
    }
    // YamaScannerの実行
    scanner->ScanPidList();

    // Show detected processes count.
    LOGINFO("Suspicious Processes Count: {}", scanner->suspiciousProcessList->size());

    // write eventlog
    if (context->canRecordEventlog) {
        if (scanner->suspiciousProcessList->size() == 0) {
            EventWriteNoDetection();
        } else {
            EventWriteDetectsMalware();
        }
    }

    // Generate report
    yama::Reporter *reporter = new yama::Reporter(context, scanner->suspiciousProcessList);
    std::string* strReport = nullptr;
    if (isJson) {
        strReport = reporter->GenerateJsonReport();
    } else {
        strReport = reporter->GenerateTextReport();
    }

    // ★変更: 結果をコンソール出力やファイル出力ではなく、呼び出し元へ返却 ★
    if(result != nullptr) {
        *result = _strdup(strReport->c_str());
    }

    if (context->canRecordEventlog) { 
        EventWriteProcessStopped(); 
        EventUnregisterYAMA();
    }

    return 0;
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