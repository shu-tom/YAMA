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

    std::map<uint64_t /*BaseVirtualAddress*/, MemoryBaseRegion*>::iterator iterAddress_MemeryBaseRegion = proc->MemoryBaseEntries.begin();
    while (iterAddress_MemeryBaseRegion != proc->MemoryBaseEntries.end()) {
        MemoryBaseRegion* BaseRegion = iterAddress_MemeryBaseRegion->second;
        std::map<uint64_t, MemoryRegion*>::iterator iterAddress_SubRegion = BaseRegion->SubRegions.begin();
        while (iterAddress_SubRegion != BaseRegion->SubRegions.end()) {
            MemoryRegion* Region = iterAddress_SubRegion->second;
            if (strcmp(Region->MemState, "MEM_COMMIT") == 0 && strcmp(Region->MemType, "MEM_PRIVATE") == 0) {
                if (strstr(Region->MemProtect, "X") != nullptr) {  // only scan executable region.
                    if (Region->RegionSize > 0 && Region->RegionSize < 50 * 1024 * 1024) { // サイズ制限: 50MB
                        try {
                            // callocの代わりに例外安全なuniqueポインタを使用
                            std::unique_ptr<unsigned char[]> buffer(new unsigned char[Region->RegionSize]());

                            // ダンプ操作を例外処理で保護
                            if (Region->DumpRegion(buffer.get(), Region->RegionSize, nullptr)) {
                                // スキャン実行
                                this->yrManager->YrScanBuffer(buffer.get(), Region->RegionSize, reinterpret_cast<void*>(yrResult));
                            }
                        }
                        catch (const std::exception& ex) {
                            LOGERROR("Exception in memory scan for region {:#x}: {}", Region->StartVa, ex.what());
                        }
                    }
                    else {
                        LOGWARN("Skipping oversized memory region: {:#x} (size: {})", Region->StartVa, Region->RegionSize);
                    }
                }
            }
            iterAddress_SubRegion++;
        }
        iterAddress_MemeryBaseRegion++;
    }
    return yrResult;
}

}  // namespace yama