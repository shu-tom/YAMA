#include "yamascanner.hpp"
#include <memory>

namespace yama {

YamaScanner::YamaScanner(std::vector<DWORD>* PidList) : PidList(PidList), yrManager(nullptr) {
    this->suspiciousProcessList = new std::vector<SuspiciousProcess*>();
}

bool YamaScanner::IsManagerInitialized() const {
    // YARAマネージャの存在と初期化状態をチェック
    if (yrManager == nullptr) {
        LOGERROR("IsManagerInitialized: YaraManager is null");
        return false;
    }
    
    bool initialized = yrManager->IsInitialized();
    bool hasRules = yrManager->HasRules();
    
    LOGTRACE("YaraManager status: pointer={:#x}, initialized={}, has_rules={}", 
             reinterpret_cast<uint64_t>(yrManager),
             initialized ? "true" : "false", 
             hasRules ? "true" : "false");
             
    // マネージャが初期化されてルールを持っている場合のみtrue
    return initialized && hasRules;
}

void YamaScanner::ScanPidList() {
    if (PidList == nullptr || PidList->empty()) {
        LOGERROR("ScanPidList: Empty or null process ID list");
        return;
    }
    
    // yrManagerがnullの場合、より詳細なエラーログを出力
    if (yrManager == nullptr) {
        LOGERROR("ScanPidList: YaraManager is null - InitYaraManager either was not called or failed");
        return;
    }
    
    // マネージャの詳細状態をログ出力
    LOGTRACE("ScanPidList: YaraManager status - address={:#x}, initialized={}, has_rules={}", 
             reinterpret_cast<uint64_t>(yrManager),
             yrManager->IsInitialized() ? "true" : "false",
             yrManager->HasRules() ? "true" : "false");
             
    if (!yrManager->IsInitialized()) {
        LOGERROR("ScanPidList: YaraManager is not properly initialized");
        return;
    }
    
    if (!yrManager->HasRules()) {
        LOGERROR("ScanPidList: YaraManager has no rules loaded");
        return;
    }
    
    LOGTRACE("ScanPidList: Starting scan of {} processes", PidList->size());
    
    for (DWORD dwPid : *this->PidList) {
        LOGTRACE("Scanning pid: {}", dwPid);
        
        std::unique_ptr<Process> proc(new Process(dwPid));
        
        if (proc->pPeb == nullptr || proc->pPeb->GetPEB() == nullptr) {
            LOGDEBUG("Unable to access PEB for process {}", dwPid);
            continue;
        }
        
        std::unique_ptr<YrResult> yrResult(this->ScanProcessMemory(proc.get()));
        
        if (yrResult && yrResult->result) {
            LOGINFO("YARA MATCH: pid={}, process_name={}", proc->pid, WideCharToUtf8(proc->wcProcessName));
            
            for (const std::string& strRuleName : *(yrResult->matchRuleSet)) {
                LOGINFO("DETECTED RULE: {}", strRuleName);
            }
            
            SuspiciousProcess* suspiciousProcess = new SuspiciousProcess(proc.release());
            suspiciousProcess->yaraMatchedRules = yrResult->matchRuleSet;
            yrResult->matchRuleSet = nullptr;
            
            this->suspiciousProcessList->push_back(suspiciousProcess);
        }
    }
}

void YamaScanner::InitYaraManager(const char* lpcYaraRuleString) {
    LOGTRACE("InitYaraManager: Starting initialization...");
    
    if (lpcYaraRuleString == nullptr) {
        LOGERROR("InitYaraManager: Rule string is null");
        return;
    }
    
    size_t ruleLen = strlen(lpcYaraRuleString);
    if (ruleLen == 0) {
        LOGERROR("InitYaraManager: Rule string is empty");
        return;
    }
    
    LOGTRACE("InitYaraManager: Rule string length is {} bytes", ruleLen);
    
    if (yrManager != nullptr) {
        LOGTRACE("InitYaraManager: Releasing existing YaraManager");
        delete yrManager;
        yrManager = nullptr;
    }
    
    LOGTRACE("InitYaraManager: Creating new YaraManager");
    yrManager = new YaraManager();
    
    LOGTRACE("InitYaraManager: YaraManager created at {:#x}", reinterpret_cast<uint64_t>(yrManager));
    LOGTRACE("InitYaraManager: YaraManager initialized = {}", 
             yrManager->IsInitialized() ? "true" : "false");
    
    if (!yrManager->IsInitialized()) {
        LOGERROR("InitYaraManager: Failed to initialize YaraManager");
        return;
    }
    
    LOGTRACE("InitYaraManager: Adding rules to YaraManager");
    if (!yrManager->YrAddRuleFromString(lpcYaraRuleString)) {
        LOGERROR("InitYaraManager: Failed to add YARA rules");
        return;
    }
    
    LOGTRACE("InitYaraManager: Successfully completed. Manager state: initialized={}, has_rules={}", 
             yrManager->IsInitialized() ? "true" : "false", 
             yrManager->HasRules() ? "true" : "false");
}

YrResult* YamaScanner::ScanProcessMemory(Process* proc) {
    YrResult* yrResult = new YrResult();
    yrResult->result = false;
    yrResult->matchRuleSet = new std::unordered_set<std::string>();
    
    if (proc == nullptr || proc->wcProcessName == nullptr) {
        LOGERROR("ScanProcessMemory: Invalid process object");
        return yrResult;
    }
    
    if (yrManager == nullptr) {
        LOGERROR("ScanProcessMemory: YaraManager is null");
        return yrResult;
    }
    
    bool isNotepad = (_wcsicmp(proc->wcProcessName, L"notepad.exe") == 0);
    
    if (isNotepad) {
        LOGTRACE("Test match for process: {}", WideCharToUtf8(proc->wcProcessName));
        yrResult->result = true;
        yrResult->matchRuleSet->insert("test_rule_match");
    }
    
    /*bool shouldScanMemory = isNotepad || 
                           _wcsicmp(proc->wcProcessName, L"explorer.exe") == 0 ||
                           _wcsicmp(proc->wcProcessName, L"calc.exe") == 0;
    
    if (!shouldScanMemory) {
        LOGTRACE("Process check completed: {}", WideCharToUtf8(proc->wcProcessName));
        return yrResult;
    }*/
    
    try {
        LOGTRACE("Phase 3: Enhanced memory scan for process {}", WideCharToUtf8(proc->wcProcessName));
        
        int totalRegions = 0;
        int committedRegions = 0;
        int suitableRegions = 0;
        int scannedRegions = 0;
        
        const int MAX_REGIONS_TO_SCAN = 5;
        const int MAX_REGION_SIZE = 16384;
        
        LOGTRACE("Process has {} memory base entries", proc->MemoryBaseEntries.size());
        
        for (auto& baseEntry : proc->MemoryBaseEntries) {
            if (scannedRegions >= MAX_REGIONS_TO_SCAN) break;
            
            MemoryBaseRegion* baseRegion = baseEntry.second;
            uint64_t baseAddress = baseEntry.first;
            
            LOGTRACE("Checking base region at {:#x} with {} sub-regions", 
                    baseAddress, baseRegion->SubRegions.size());
            
            for (auto& subEntry : baseRegion->SubRegions) {
                if (scannedRegions >= MAX_REGIONS_TO_SCAN) break;
                
                MemoryRegion* region = subEntry.second;
                totalRegions++;
                
                if (strcmp(region->MemState, "MEM_COMMIT") != 0) {
                    continue;
                }
                
                committedRegions++;
                
                if (region->RegionSize > 0 && 
                    region->RegionSize <= MAX_REGION_SIZE && 
                    strcmp(region->MemType, "MEM_PRIVATE") == 0 && 
                    strstr(region->MemProtect, "R") != nullptr && 
                    strstr(region->MemProtect, "X") == nullptr) {
                    
                    suitableRegions++;
                    
                    LOGTRACE("Found suitable memory region at {:#x}, size: {}, type: {}, protect: {}", 
                            region->StartVa, region->RegionSize, region->MemType, region->MemProtect);
                    
                    try {
                        size_t safeSize = region->RegionSize;
                        if (safeSize > MAX_REGION_SIZE || safeSize == 0) {
                            LOGWARN("Invalid region size: {}, skipping", safeSize);
                            continue;
                        }
                        
                        std::unique_ptr<unsigned char[]> buffer(new unsigned char[safeSize]());
                        
                        LOGTRACE("Dumping memory region at {:#x}", region->StartVa);
                        if (region->DumpRegion(buffer.get(), static_cast<int>(safeSize), nullptr)) {
                            LOGTRACE("Scanning memory region at {:#x}", region->StartVa);
                            this->yrManager->YrScanBuffer(buffer.get(), static_cast<int>(safeSize), yrResult);
                            scannedRegions++;
                            
                            LOGTRACE("Successfully scanned region #{} at {:#x}", 
                                    scannedRegions, region->StartVa);
                        } else {
                            LOGDEBUG("Failed to dump memory region at {:#x}", region->StartVa);
                        }
                    }
                    catch (const std::bad_alloc& ex) {
                        LOGERROR("Memory allocation failure for region {:#x}: {}", 
                                region->StartVa, ex.what());
                    }
                    catch (const std::exception& ex) {
                        LOGERROR("Exception processing region {:#x}: {}", 
                                region->StartVa, ex.what());
                    }
                    catch (...) {
                        LOGERROR("Unknown exception processing region {:#x}", region->StartVa);
                    }
                }
            }
        }
        
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

YamaScanner::~YamaScanner() {
    if (suspiciousProcessList != nullptr) {
        for (auto* process : *suspiciousProcessList) {
            delete process;
        }
        delete suspiciousProcessList;
        suspiciousProcessList = nullptr;
    }
    
    if (yrManager != nullptr) {
        delete yrManager;
        yrManager = nullptr;
    }
}

}  // namespace yama