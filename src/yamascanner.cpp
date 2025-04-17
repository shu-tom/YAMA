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
    std::vector<MemoryRegion*> *yaraMatchedRegions = new std::vector<MemoryRegion*>();

    // Phase 2: 安全なプロセスのみ実際にスキャン
    bool safeToScan = false;
    const wchar_t* safeProcesses[] = {
        L"notepad.exe", L"calc.exe", L"explorer.exe", L"mspaint.exe" 
    };
    
    // プロセスが安全なリストに含まれているか確認
    if (proc->wcProcessName != nullptr) {
        for (const wchar_t* safeProcName : safeProcesses) {
            if (_wcsicmp(proc->wcProcessName, safeProcName) == 0) {
                safeToScan = true;
                LOGTRACE("Process selected for full scan: {}", WideCharToUtf8(proc->wcProcessName));
                break;
            }
        }
    }
    
    // 安全でないプロセスは早期リターン
    if (!safeToScan) {
        LOGTRACE("Skipping full scan for process: {}", WideCharToUtf8(proc->wcProcessName));
        return yrResult;
    }

    // 選択されたプロセスのみ実際のスキャン実行
    // Phase 2では少数のメモリ領域のみスキャン
    int scannedRegionsCount = 0;
    const int MAX_REGIONS_TO_SCAN = 5;  // 最大スキャン領域数

    std::map<uint64_t /*BaseVirtualAddress*/, MemoryBaseRegion*>::iterator iterAddress_MemeryBaseRegion 
        = proc->MemoryBaseEntries.begin();
    
    while (iterAddress_MemeryBaseRegion != proc->MemoryBaseEntries.end() && scannedRegionsCount < MAX_REGIONS_TO_SCAN) {
        MemoryBaseRegion* BaseRegion = iterAddress_MemeryBaseRegion->second;
        
        std::map<uint64_t, MemoryRegion*>::iterator iterAddress_SubRegion = BaseRegion->SubRegions.begin();
        while (iterAddress_SubRegion != BaseRegion->SubRegions.end() && scannedRegionsCount < MAX_REGIONS_TO_SCAN) {
            MemoryRegion* Region = iterAddress_SubRegion->second;
            if (strcmp(Region->MemState, "MEM_COMMIT") == 0 && strcmp(Region->MemType, "MEM_PRIVATE") == 0) {
                if (strstr(Region->MemProtect, "X") != nullptr) {  // only scan executable region.
                    if (Region->RegionSize > 0 && Region->RegionSize < 1 * 1024 * 1024) { // 1MB以下のリージョンのみ
                        try {
                            // 安全なメモリ管理を実施
                            std::unique_ptr<unsigned char[]> buffer(new unsigned char[Region->RegionSize]());

                            if (Region->DumpRegion(buffer.get(), Region->RegionSize, nullptr)) {
                                this->yrManager->YrScanBuffer(buffer.get(), Region->RegionSize, reinterpret_cast<void*>(yrResult));
                                scannedRegionsCount++;
                                LOGTRACE("Scanned memory region #{} at {:#x}, size: {}", 
                                          scannedRegionsCount, Region->StartVa, Region->RegionSize);
                            }
                        }
                        catch (const std::exception& ex) {
                            LOGERROR("Exception in memory scan for region {:#x}: {}", Region->StartVa, ex.what());
                        }
                    }
                }
            }
            iterAddress_SubRegion++;
        }
        iterAddress_MemeryBaseRegion++;
    }
    
    LOGTRACE("Completed scanning {} memory regions for process {} ({})",
             scannedRegionsCount, proc->pid, WideCharToUtf8(proc->wcProcessName));
    
    return yrResult;
}

}  // namespace yama