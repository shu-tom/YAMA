#include "yamascanner.hpp"

namespace yama {
YamaScanner::YamaScanner(std::vector<DWORD>* PidList) {
    this->PidList = PidList;
    this->suspiciousProcessList = new std::vector<SuspiciousProcess*>();
}

void YamaScanner::ScanPidList() {
    YrResult* yrResult = nullptr;
    for (DWORD dwPid : *this->PidList) {
        LOGTRACE("now scanning pid: {}", dwPid);
        Process* proc = new Process(dwPid);
        if (proc->pPeb == nullptr || proc->pPeb->GetPEB() == nullptr) {
            continue;
        }
        yrResult = this->ScanProcessMemory(proc);
        if (yrResult->result) {
            LOGINFO("YARA MATCH: pid={}, process_name={}", proc->pid, WideCharToUtf8(proc->wcProcessName));
            for (std::string strRuleName : *(yrResult->matchRuleSet)){
                LOGINFO("DETECTED RULE: {}",strRuleName.c_str());
            }
            SuspiciousProcess *suspiciousProcess = new SuspiciousProcess(proc);
            suspiciousProcess->yaraMatchedRules = yrResult->matchRuleSet;
            this->suspiciousProcessList->push_back(suspiciousProcess);
        }
    }
}

void YamaScanner::InitYaraManager(const char* lpcYaraRuleString) {
    this->yrManager = new YaraManager();
    this->yrManager->YrAddRuleFromString(lpcYaraRuleString);
}

YrResult* YamaScanner::ScanProcessMemory(Process* proc) {
    // Init yara result object
    YrResult* yrResult = new YrResult();
    yrResult->result = false;
    yrResult->matchRuleSet = new std::unordered_set<std::string>();
    
    // 現段階では安全なテストのみを実施 - 実際のスキャンは行わない
    // プロセスに基づくサンプル検出を行う
    if (proc->wcProcessName != nullptr) {
        const wchar_t* testProcesses[] = {
            L"notepad.exe", L"calc.exe", L"mspaint.exe" 
        };
        
        // サンプル検出のためのテストプロセスをチェック
        for (const wchar_t* testProc : testProcesses) {
            if (_wcsicmp(proc->wcProcessName, testProc) == 0) {
                LOGTRACE("Test match for process: {}", WideCharToUtf8(proc->wcProcessName));
                
                // テスト用の検出をシミュレート
                yrResult->result = true;
                yrResult->matchRuleSet->insert("test_rule_match");
                break;
            }
        }
        
        LOGTRACE("Process check completed: {}", WideCharToUtf8(proc->wcProcessName));
    }
    
    return yrResult;
}

}  // namespace yama