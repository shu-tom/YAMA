#include "yaramanager.hpp"
#include "yamascanner.hpp" // YamaScannerクラスのヘッダーをインクルード
#include <iomanip> // setfill, setwに必要
#include <sstream> // stringstream用

namespace yama {

YaraManager::YaraManager() {
    int res = yr_initialize();
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to initialize libyara. Error:0x{:x}", res);
        return;
    }
    LOGTRACE("Initialized YaraManager");
    // create yara compiler
    res = yr_compiler_create(&this->YrCompiler);
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to create yara compiler. Error:0x{:x}", res);
    }
    return;
}

bool YaraManager::YrCreateScanner() {
    int dwRes = yr_scanner_create(this->YrRules, &this->YrScanner);
    if (dwRes != ERROR_SUCCESS) {
        LOGERROR("Failed to create scanner. Error:0x{:x}", dwRes);
    }
    return true;
}

bool YaraManager::YrAddRuleFromString(const char* strRule) {
    int res = yr_compiler_add_string(this->YrCompiler, strRule, nullptr);
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to add rule. Error:0x{:x}", res);
        return false;
    }
    LOGTRACE("Add new rule to compiler.");

    res = yr_compiler_get_rules(this->YrCompiler, &this->YrRules);
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to get rules from compiler. Error:0x{:x}", res);
        return false;
    }
    LOGTRACE("Get {:d} rules from compiler.", this->YrRules->num_rules);
    return true;
}

// YARAスキャンコールバック関数の修正
int YaraManager::YrScanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data,
                                void* user_data) {
    // NULL安全性チェック
    if (user_data == nullptr) {
        LOGERROR("YrScanCallback: user_data is NULL");
        return CALLBACK_ERROR;
    }

    try {
        // user_dataが実際にはYrResultオブジェクトへのポインタ
        auto yrResult = static_cast<YrResult*>(user_data);
        if (yrResult == nullptr) {
            LOGERROR("YrScanCallback: Invalid YrResult pointer");
            return CALLBACK_ERROR;
        }
        
        // メッセージ種別の処理
        switch (message) {
            case CALLBACK_MSG_RULE_MATCHING: {
                // ルールマッチング時の安全な処理
                if (message_data == nullptr) {
                    LOGERROR("YrScanCallback: message_data is NULL for CALLBACK_MSG_RULE_MATCHING");
                    return CALLBACK_ERROR;
                }

                auto rule = static_cast<YR_RULE*>(message_data);
                if (rule == nullptr || rule->identifier == nullptr) {
                    LOGERROR("YrScanCallback: rule or rule identifier is NULL");
                    return CALLBACK_ERROR;
                }

                // マッチしたルールの識別子を記録
                std::string ruleName(rule->identifier);
                LOGTRACE("YrScanCallback: Rule matched: {}", ruleName);
                
                // 結果オブジェクトを更新
                yrResult->result = true;
                if (yrResult->matchRuleSet != nullptr) {
                    yrResult->matchRuleSet->insert(ruleName);
                }
                
                return CALLBACK_CONTINUE;
            }
            case CALLBACK_MSG_RULE_NOT_MATCHING:
                return CALLBACK_CONTINUE;
            case CALLBACK_MSG_SCAN_FINISHED:
                return CALLBACK_CONTINUE;
            default:
                return CALLBACK_ERROR;
        }
    }
    catch (const std::exception& ex) {
        LOGERROR("Exception in YrScanCallback: {}", ex.what());
        return CALLBACK_ERROR;
    }
    catch (...) {
        LOGERROR("Unknown exception in YrScanCallback");
        return CALLBACK_ERROR;
    }
}

// SEHを使用するヘルパー関数を追加
int YaraManager::ScanMemWithSEH(YR_RULES* rules, const unsigned char* buffer, 
                               int size, int flags, YR_CALLBACK_FUNC callback, 
                               void* userData, int timeout) {
    __try {
        return yr_rules_scan_mem(
            rules,     // YARAルール
            buffer,    // スキャン対象バッファ
            size,      // バッファサイズ
            flags,     // スキャンフラグ
            callback,  // コールバック関数
            userData,  // コールバック用データ
            timeout    // タイムアウト（秒）
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOGERROR("SEH exception in yr_rules_scan_mem: {}", GetExceptionCode());
        return ERROR_INTERNAL_FATAL_ERROR;
    }
}

void YaraManager::YrScanBuffer(const unsigned char* lpBuffer, int dwBufferSize, void* lpUserData) {
    __try {
        // バッファとサイズの検証
        if (lpBuffer == nullptr || dwBufferSize <= 0) {
            LOGTRACE("YrScanBuffer: Invalid buffer parameters. Buffer: {:#x}, Size: {}", 
                    reinterpret_cast<uint64_t>(lpBuffer), dwBufferSize);
            return;
        }
        
        // YrRulesの検証を強化
        if (this == nullptr) {
            LOGERROR("YrScanBuffer: 'this' pointer is NULL");
            return;
        }
        
        if (this->YrRules == nullptr) {
            LOGTRACE("YrScanBuffer: YrRules is NULL");
            return;
        }

        // フェーズ2: 限定的なスキャンを有効化
        // バッファサイズを厳格に制限
        const int MAX_SAFE_BUFFER_SIZE = 4096; // 4KB制限
        int safeSize = (dwBufferSize > MAX_SAFE_BUFFER_SIZE) ? MAX_SAFE_BUFFER_SIZE : dwBufferSize;

        LOGTRACE("YrScanBuffer: Phase 2 - Limited scan mode. Va:{:#x} Size:{} (limited from {})", 
                reinterpret_cast<uint64_t>(lpBuffer), safeSize, dwBufferSize);

        // 空のバッファや小さすぎるバッファは処理しない
        if (safeSize <= 16) {
            LOGDEBUG("YrScanBuffer: Buffer too small for meaningful scan, skipping");
            return;
        }

        // スキャン開始（SEH例外処理でラップ済み）
        try {
            // 最小限のスキャン設定
            int timeout = 2; // 短いタイムアウト
            int flags = SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_FAST_MODE;
            
            LOGTRACE("YrScanBuffer: Starting limited scan with timeout {}s", timeout);
            
            int result = ScanMemWithSEH(
                this->YrRules, lpBuffer, safeSize, flags, 
                this->YrScanCallback, lpUserData, timeout);
                
            if (result == ERROR_SUCCESS) {
                LOGTRACE("YrScanBuffer: Scan completed successfully");
            } else if (result == ERROR_SCAN_TIMEOUT) {
                LOGWARN("YrScanBuffer: Scan timeout after {} seconds", timeout);
            } else {
                LOGWARN("YrScanBuffer: Scan returned error code: {}", result);
            }
        }
        catch (const std::exception& ex) {
            LOGERROR("Exception in YrScanBuffer: {}", ex.what());
        }
        catch (...) {
            LOGERROR("Unknown exception in YrScanBuffer");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOGERROR("SEH exception in YrScanBuffer: Exception code: {:#x}", GetExceptionCode());
    }
}

YaraManager::~YaraManager() {
    if (this->YrRules != nullptr) {
        yr_rules_destroy(this->YrRules);
    }
    if (this->YrCompiler != nullptr) {
        yr_compiler_destroy(this->YrCompiler);
    }
    // if (this->YrScanner != nullptr) {
    //     yr_scanner_destroy(this->YrScanner);
    // }
    int res = yr_finalize();
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to finalize libyara. Error:0x{:x}", res);
    }
    LOGTRACE("Finalized YaraManager");
    return;
}

}  // namespace yama