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

const char* version = "1.0";

const char* banner = " __  _____   __  ______\n" 
                     " \\ \\/ / _ | /  |/  / _ |\n"
                     "  \\  / __ |/ /|_/ / __ |\n"
                     "  /_/_/ |_/_/  /_/_/ |_|\n"
                     "Yet Another Memory Analyzer for malware detection.\n";

extern "C" __declspec(dllexport) int MemoryScan() {
    // 固定設定値
    int verbosity = 0; // warn レベルに相当
    std::string strOutputPath = "./";
    bool isJson = false;
    
    // 引数パーサー削除
    // ...existing code removed: argc, argv の処理、argparse の初期化など...

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
    
    // 以下、固定動作処理
    // (イベントログのインストール／アンインストール処理は削除)
    
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
    scanner->InitYaraManager(yama::LoadYaraRuleFromResource());
    
    // Do memory scan
    if (context->canRecordEventlog) { EventWriteProcessStarted(); }
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

    // Write result into console
    std::cout << *strReport << std::endl;  

    // Write result into output directory
    std::string strReportPath = strOutputPath + "\\" +
                                yama::WideCharToUtf8(context->lpwHostName) + "_" +
                                std::string(context->lpcFilenameTime) + "_yama." +
                                (isJson ? "json" : "txt");
    LOGINFO("Report file path: {}", strReportPath)

    std::ofstream ioOutputFile(strReportPath.c_str());
    if (ioOutputFile.is_open()){
        ioOutputFile << *strReport << std::endl;
        ioOutputFile.close();
        LOGINFO("File written successfully: {}", strReportPath);
    } else {
        LOGWARN("Failed to open file: {}", strReportPath);
    }

    if (context->canRecordEventlog) { 
        EventWriteProcessStopped(); 
        EventUnregisterYAMA();
    }

    return 0;
}

#ifdef _WIN32
// DLLのエントリポイント
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){
    switch (ul_reason_for_call){
    case DLL_PROCESS_ATTACH:
        // 初期化処理があれば記述
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#endif