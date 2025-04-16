#include "yaramanager.hpp"
#include "yamascanner.hpp" // YamaScannerクラスのヘッダーをインクルード

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

void YaraManager::YrScanBuffer(const unsigned char* lpBuffer, int dwBufferSize, void* lpUserData) {
    // printf("YrScanBuffer. Va:%#.16I64x Size:%d\n",
    // reinterpret_cast<uint64_t>(lpBuffer), dwBufferSize);
    yr_rules_scan_mem(this->YrRules, lpBuffer, dwBufferSize, SCAN_FLAGS_REPORT_RULES_MATCHING,
                      this->YrScanCallback, lpUserData, 0);
    // printf("YrScanBuffer finished.\n");
    return;
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