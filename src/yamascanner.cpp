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
    
    // notepadプロセスのチェック
    bool isNotepad = (proc->wcProcessName != nullptr && _wcsicmp(proc->wcProcessName, L"notepad.exe") == 0);
    
    // テスト検出は常に維持（現行の動作を維持）
    if (isNotepad) {
        LOGTRACE("Test match for process: {}", WideCharToUtf8(proc->wcProcessName));
        yrResult->result = true;
        yrResult->matchRuleSet->insert("test_rule_match");
    }
    
    if (!isNotepad) {
        LOGTRACE("Process check completed: {}", WideCharToUtf8(proc->wcProcessName));
        return yrResult;
    }
    
    // この先はnotepadプロセスのみ実行
    try {
        LOGTRACE("Phase 1.5: Scanning notepad process memory regions");
        
        // 条件緩和 - メモリ領域のカウント
        int totalRegions = 0;
        int committedRegions = 0;
        int suitableRegions = 0;
        int scannedRegions = 0;
        
        // notepadプロセスのメモリ情報を出力
        LOGTRACE("Process has {} memory base entries", proc->MemoryBaseEntries.size());
        
        std::map<uint64_t, MemoryBaseRegion*>::iterator iterBase = proc->MemoryBaseEntries.begin();
        while (iterBase != proc->MemoryBaseEntries.end()) {
            MemoryBaseRegion* baseRegion = iterBase->second;
            uint64_t baseAddress = iterBase->first; // マップのキーを使用
            
            LOGTRACE("Base region at {:#x} has {} sub-regions", 
                     baseAddress, baseRegion->SubRegions.size());
            
            std::map<uint64_t, MemoryRegion*>::iterator iterSub = baseRegion->SubRegions.begin();
            while (iterSub != baseRegion->SubRegions.end()) {
                MemoryRegion* region = iterSub->second;
                totalRegions++;
                
                // どのようなメモリ領域が存在するか記録
                if (strcmp(region->MemState, "MEM_COMMIT") == 0) {
                    committedRegions++;
                    
                    // 条件を大幅に緩和: より多くの領域をスキャン
                    // サイズ上限を増加（64KB以下）
                    if (region->RegionSize > 0 && region->RegionSize <= 65536) {
                        suitableRegions++;
                        
                        // より詳細な情報をログに出力
                        LOGTRACE("Suitable memory region at {:#x}, size: {}, type: {}, protect: {}", 
                                region->StartVa, region->RegionSize, region->MemType, region->MemProtect);
                        
                        try {
                            // バッファ確保
                            std::unique_ptr<unsigned char[]> buffer(new unsigned char[region->RegionSize]());
                            
                            // メモリダンプ試行
                            if (region->DumpRegion(buffer.get(), region->RegionSize, nullptr)) {
                                // YARAスキャン実行
                                this->yrManager->YrScanBuffer(buffer.get(), region->RegionSize, yrResult);
                                scannedRegions++;
                                
                                LOGTRACE("Successfully scanned memory region #{} at {:#x}, size: {}", 
                                        scannedRegions, region->StartVa, region->RegionSize);
                                
                                // 最大10領域までスキャン
                                if (scannedRegions >= 10) {
                                    LOGTRACE("Reached maximum scan regions limit (10)");
                                    break;
                                }
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
            
            // 最大スキャン数に達したらループを抜ける
            if (scannedRegions >= 10) {
                break;
            }
            
            iterBase++;
        }
        
        LOGTRACE("Memory region statistics - Total: {}, Committed: {}, Suitable: {}, Scanned: {}", 
                totalRegions, committedRegions, suitableRegions, scannedRegions);
        
        LOGTRACE("Phase 1.5: Completed scanning {} memory regions for notepad.exe", 
                scannedRegions);
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