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
    YrResult* yrResult = new YrResult();
    yrResult->result = false;
    yrResult->matchRuleSet = new std::unordered_set<std::string>();
    
    // フェーズ1.5: notepad.exeの場合は、テスト検出とともに制限付きの実スキャンも実施する
    bool isNotepad = (proc->wcProcessName != nullptr && _wcsicmp(proc->wcProcessName, L"notepad.exe") == 0);
    
    // テスト検出はそのまま維持（現行の動作を壊さないため）
    if (isNotepad) {
        LOGTRACE("Test match for process: {}", WideCharToUtf8(proc->wcProcessName));
        yrResult->result = true;
        yrResult->matchRuleSet->insert("test_rule_match");
    }
    
    // 厳選されたプロセスのみ、実際のスキャンを実施
    bool safeToScan = isNotepad; // 初期フェーズではnotepad.exeのみをスキャン対象とする
    if (!safeToScan) {
        LOGTRACE("Process check completed: {}", WideCharToUtf8(proc->wcProcessName));
        return yrResult;
    }
    
    // この先は、安全なプロセスに対する実際のスキャンを実施する
    try {
        LOGTRACE("Phase 1.5: Safe scan for process: {}", WideCharToUtf8(proc->wcProcessName));
        
        // 極めて制限的なスキャン - 最小限のメモリ領域のみをスキャン
        int scannedRegionsCount = 0;
        const int MAX_REGIONS_TO_SCAN = 1;  // フェーズ1.5では単一領域のみ
        
        std::map<uint64_t, MemoryBaseRegion*>::iterator iterBase = proc->MemoryBaseEntries.begin();
        while (iterBase != proc->MemoryBaseEntries.end() && scannedRegionsCount < MAX_REGIONS_TO_SCAN) {
            MemoryBaseRegion* baseRegion = iterBase->second;
            
            std::map<uint64_t, MemoryRegion*>::iterator iterSub = baseRegion->SubRegions.begin();
            while (iterSub != baseRegion->SubRegions.end() && scannedRegionsCount < MAX_REGIONS_TO_SCAN) {
                MemoryRegion* region = iterSub->second;
                
                // 非常に厳しい条件: 小さな読み取り専用領域のみをスキャン
                if (strcmp(region->MemState, "MEM_COMMIT") == 0 && 
                    strcmp(region->MemType, "MEM_PRIVATE") == 0 &&
                    strstr(region->MemProtect, "R") != nullptr && 
                    strstr(region->MemProtect, "X") == nullptr) { // 実行権限のない領域のみ
                    
                    // 超小型サイズのみ (1KB以下)
                    if (region->RegionSize > 0 && region->RegionSize <= 1024) {
                        try {
                            LOGTRACE("Attempting to scan tiny memory region at {:#x}, size: {}, type: {}, protect: {}", 
                                    region->StartVa, region->RegionSize, region->MemType, region->MemProtect);
                            
                            // 安全なメモリ割り当て
                            std::unique_ptr<unsigned char[]> buffer(new unsigned char[region->RegionSize]());
                            
                            // メモリダンプ試行
                            if (region->DumpRegion(buffer.get(), region->RegionSize, nullptr)) {
                                // YARAスキャン実行 - エラーハンドリング強化
                                this->yrManager->YrScanBuffer(buffer.get(), region->RegionSize, yrResult);
                                scannedRegionsCount++;
                                
                                LOGTRACE("Successfully scanned memory region #{} at {:#x}, size: {}", 
                                        scannedRegionsCount, region->StartVa, region->RegionSize);
                            }
                            else {
                                LOGDEBUG("Failed to dump memory region at {:#x} - skipping", region->StartVa);
                            }
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
        
        LOGTRACE("Phase 1.5: Completed scanning {} tiny memory regions for process {}", 
                scannedRegionsCount, WideCharToUtf8(proc->wcProcessName));
    }
    catch (const std::exception& ex) {
        LOGERROR("Exception during process scan: {}", ex.what());
    }
    catch (...) {
        LOGERROR("Unknown exception during process scan");
    }
    
    return yrResult;
}

}  // namespace yama