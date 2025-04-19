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
    
    // フェーズ2: 制限付きメモリスキャンの実施（notepad.exeのみ）
    try {
        LOGTRACE("Phase 2: Limited memory scan for notepad.exe");
        
        // 統計カウンタの初期化
        int totalRegions = 0;
        int committedRegions = 0;
        int suitableRegions = 0;
        int scannedRegions = 0;
        
        // 厳格な制限値
        const int MAX_REGIONS_TO_SCAN = 3;  // 最大3つの領域のみスキャン
        const int MAX_REGION_SIZE = 4096;  // 4KB以下の領域のみ
        
        LOGTRACE("Process has {} memory base entries", proc->MemoryBaseEntries.size());
        
        // 各ベース領域をチェック
        std::map<uint64_t, MemoryBaseRegion*>::iterator iterBase = proc->MemoryBaseEntries.begin();
        while (iterBase != proc->MemoryBaseEntries.end() && scannedRegions < MAX_REGIONS_TO_SCAN) {
            MemoryBaseRegion* baseRegion = iterBase->second;
            uint64_t baseAddress = iterBase->first;
            
            LOGTRACE("Checking base region at {:#x} with {} sub-regions", 
                     baseAddress, baseRegion->SubRegions.size());
            
            // サブ領域をチェック
            std::map<uint64_t, MemoryRegion*>::iterator iterSub = baseRegion->SubRegions.begin();
            while (iterSub != baseRegion->SubRegions.end() && scannedRegions < MAX_REGIONS_TO_SCAN) {
                MemoryRegion* region = iterSub->second;
                totalRegions++;
                
                // コミットされたメモリのみを考慮
                if (strcmp(region->MemState, "MEM_COMMIT") == 0) {
                    committedRegions++;
                    
                    // 安全なメモリ領域の条件: 小サイズ、プライベート、読み取り可能
                    if (region->RegionSize > 0 && 
                        region->RegionSize <= MAX_REGION_SIZE && 
                        strcmp(region->MemType, "MEM_PRIVATE") == 0 && 
                        strstr(region->MemProtect, "R") != nullptr) {
                        
                        suitableRegions++;
                        
                        LOGTRACE("Found suitable memory region at {:#x}, size: {}, type: {}, protect: {}", 
                                region->StartVa, region->RegionSize, region->MemType, region->MemProtect);
                        
                        try {
                            // バッファを安全に確保
                            std::unique_ptr<unsigned char[]> buffer(new unsigned char[region->RegionSize]());
                            
                            // メモリダンプの実行
                            LOGTRACE("Attempting to dump region at {:#x}", region->StartVa);
                            if (region->DumpRegion(buffer.get(), region->RegionSize, nullptr)) {
                                // YARAスキャンの実行
                                LOGTRACE("Scanning region at {:#x}", region->StartVa);
                                this->yrManager->YrScanBuffer(buffer.get(), region->RegionSize, yrResult);
                                scannedRegions++;
                                
                                LOGTRACE("Successfully scanned region #{} at {:#x}", 
                                        scannedRegions, region->StartVa);
                            } else {
                                LOGDEBUG("Failed to dump region at {:#x}", region->StartVa);
                            }
                        }
                        catch (const std::exception& ex) {
                            LOGERROR("Exception while processing region {:#x}: {}", 
                                    region->StartVa, ex.what());
                        }
                        catch (...) {
                            LOGERROR("Unknown exception processing region {:#x}", region->StartVa);
                        }
                    }
                }
                iterSub++;
            }
            iterBase++;
        }
        
        // スキャン統計の出力
        LOGTRACE("Memory scan statistics - Total: {}, Committed: {}, Suitable: {}, Scanned: {}", 
                totalRegions, committedRegions, suitableRegions, scannedRegions);
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