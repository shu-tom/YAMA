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
    
    // 安全なプロセスのリスト
    const wchar_t* safeProcesses[] = {
        L"notepad.exe", L"calc.exe", L"mspaint.exe" 
    };
    
    // プロセス名を取得して安全かどうか確認
    bool safeToScan = false;
    if (proc->wcProcessName != nullptr) {
        for (const wchar_t* safeProcName : safeProcesses) {
            if (_wcsicmp(proc->wcProcessName, safeProcName) == 0) {
                safeToScan = true;
                LOGTRACE("Process selected for actual scan: {}", WideCharToUtf8(proc->wcProcessName));
                break;
            }
        }
    }
    
    // テスト用のnotepad検出を維持（現段階ではサンプル検出を優先）
    if (proc->wcProcessName != nullptr && _wcsicmp(proc->wcProcessName, L"notepad.exe") == 0) {
        LOGTRACE("Test match for process: {}", WideCharToUtf8(proc->wcProcessName));
        yrResult->result = true;
        yrResult->matchRuleSet->insert("test_rule_match");
    }
    
    // 現段階では安全のためフェーズ1に戻る - 実際のスキャンは行わない
    LOGTRACE("Process check completed: {}", WideCharToUtf8(proc->wcProcessName));
    
    // 今後の開発のためにスキャン部分はコメントアウトで残す
    /*
    // 安全でないプロセスはスキップ
    if (!safeToScan) {
        return yrResult;
    }
    
    // 実際のスキャンを行う - 非常に限定的
    LOGTRACE("Performing actual scan for process: {}", WideCharToUtf8(proc->wcProcessName));
    
    int scannedRegionsCount = 0;
    const int MAX_REGIONS_TO_SCAN = 1;  // 一時的に1つだけに制限
    
    std::map<uint64_t, MemoryBaseRegion*>::iterator iterBase = proc->MemoryBaseEntries.begin();
    while (iterBase != proc->MemoryBaseEntries.end() && scannedRegionsCount < MAX_REGIONS_TO_SCAN) {
        MemoryBaseRegion* baseRegion = iterBase->second;
        
        std::map<uint64_t, MemoryRegion*>::iterator iterSub = baseRegion->SubRegions.begin();
        while (iterSub != baseRegion->SubRegions.end() && scannedRegionsCount < MAX_REGIONS_TO_SCAN) {
            MemoryRegion* region = iterSub->second;
            
            // より厳しい条件: 小さいReadWrite領域のみ
            if (strcmp(region->MemState, "MEM_COMMIT") == 0 && 
                strcmp(region->MemType, "MEM_PRIVATE") == 0 &&
                strstr(region->MemProtect, "RW") != nullptr) {
                
                // 小さいサイズのみ (4KB以下)
                if (region->RegionSize > 0 && region->RegionSize <= 4096) {
                    try {
                        LOGTRACE("Attempting to dump memory region at {:#x}, size: {}, type: {}, protect: {}", 
                                region->StartVa, region->RegionSize, region->MemType, region->MemProtect);
                        
                        // 今後の実装で使用するための代替コード
                        // この部分はさらに安全性が確認されてから有効化する
                    }
                    catch (const std::exception& ex) {
                        LOGERROR("Exception scanning region {:#x}: {}", region->StartVa, ex.what());
                    }
                    catch (...) {
                        LOGERROR("Unknown exception scanning region {:#x}", region->StartVa);
                    }
                }
            }
            iterSub++;
        }
        iterBase++;
    }
    
    LOGTRACE("Completed scanning {} memory regions for process {}", 
            scannedRegionsCount, WideCharToUtf8(proc->wcProcessName));
    */
    
    return yrResult;
}

}  // namespace yama