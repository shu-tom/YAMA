#include "yaramanager.hpp"
#include "yamascanner.hpp" // YamaScannerクラスのヘッダーをインクルード
#include <iomanip> // setfill, setwに必要
#include <sstream> // stringstream用
#include <mutex> // スレッドセーフなアクセスのため
#include <algorithm> // std::min用

namespace yama {

// スレッドセーフなアクセスのためのミューテックス
static std::mutex yaraRulesMutex;

YaraManager::YaraManager() : YrCompiler(nullptr), YrScanner(nullptr), YrRules(nullptr), m_initialized(false) {
    // YARA初期化のスレッドセーフな保証
    std::lock_guard<std::mutex> lock(yaraRulesMutex);
    
    int res = yr_initialize();
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to initialize libyara. Error:0x{:x}", res);
        return;
    }
    LOGTRACE("Initialized YaraManager");
    
    // YARAコンパイラの作成
    res = yr_compiler_create(&this->YrCompiler);
    if (res != ERROR_SUCCESS) {
        LOGERROR("Failed to create yara compiler. Error:0x{:x}", res);
        // 初期化に失敗した場合、YARAをクリーンアップ
        yr_finalize();
        return;
    }
    
    // 初期化成功フラグ設定
    m_initialized = true;
    LOGTRACE("YaraManager successfully initialized");
}

bool YaraManager::YrCreateScanner() {
    if (!m_initialized || YrRules == nullptr) {
        LOGERROR("Cannot create scanner: YaraManager not properly initialized or no rules loaded");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(yaraRulesMutex);
    int dwRes = yr_scanner_create(this->YrRules, &this->YrScanner);
    if (dwRes != ERROR_SUCCESS) {
        LOGERROR("Failed to create scanner. Error:0x{:x}", dwRes);
        return false;
    }
    return true;
}

bool YaraManager::IsValidRule(const char* strRule) {
    if (strRule == nullptr || *strRule == '\0') {
        LOGERROR("Invalid rule: Rule string is null or empty");
        return false;
    }
    
    // 基本的な構文チェック（ruleキーワードが存在するか）
    if (strstr(strRule, "rule ") == nullptr) {
        LOGERROR("Invalid rule: Missing 'rule' keyword");
        return false;
    }
    
    // 適切なバランスチェック（括弧、中括弧）
    int braces = 0, parentheses = 0;
    for (const char* p = strRule; *p; ++p) {
        if (*p == '{') braces++;
        else if (*p == '}') braces--;
        else if (*p == '(') parentheses++;
        else if (*p == ')') parentheses--;
        
        // アンバランスをチェック
        if (braces < 0 || parentheses < 0) {
            LOGERROR("Invalid rule: Unbalanced braces or parentheses");
            return false;
        }
    }
    
    if (braces != 0 || parentheses != 0) {
        LOGERROR("Invalid rule: Unclosed braces or parentheses");
        return false;
    }
    
    return true;
}

bool YaraManager::YrAddRuleFromString(const char* strRule) {
    if (!m_initialized) {
        LOGERROR("Cannot add rule: YaraManager not properly initialized");
        return false;
    }
    
    if (!IsValidRule(strRule)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(yaraRulesMutex);
    
    // 既存のルールがあればクリア
    if (this->YrRules != nullptr) {
        yr_rules_destroy(this->YrRules);
        this->YrRules = nullptr;
    }
    
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
    
    if (this->YrRules == nullptr) {
        LOGERROR("Failed to get rules from compiler: YrRules is null");
        return false;
    }
    
    if (this->YrRules->num_rules == 0) {
        LOGWARN("Warning: Compiled rules contain 0 rules");
    } else {
        LOGTRACE("Successfully compiled {:d} rules", this->YrRules->num_rules);
    }
    
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

// SEHを使用するヘルパー関数
int YaraManager::ScanMemWithSEH(YR_RULES* rules, const unsigned char* buffer, 
                              int size, int flags, YR_CALLBACK_FUNC callback, 
                              void* userData, int timeout) {
    if (rules == nullptr || buffer == nullptr || size <= 0) {
        LOGERROR("ScanMemWithSEH: Invalid parameter - rules={:#x}, buffer={:#x}, size={}",
                 reinterpret_cast<uint64_t>(rules),
                 reinterpret_cast<uint64_t>(buffer),
                 size);
        return ERROR_INVALID_PARAMETER;
    }
    
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

// SEH例外処理とC++例外処理を分離
void YaraManager::YrScanBuffer(const unsigned char* lpBuffer, int dwBufferSize, void* lpUserData) {
    // 前処理 - バッファとパラメータの検証
    if (lpBuffer == nullptr || dwBufferSize <= 0) {
        LOGERROR("YrScanBuffer: Invalid buffer parameters. Buffer: {:#x}, Size: {}", 
                reinterpret_cast<uint64_t>(lpBuffer), dwBufferSize);
        return;
    }
    
    // 初期化とYrRulesの検証
    if (!m_initialized) {
        LOGERROR("YrScanBuffer: YaraManager not properly initialized");
        return;
    }
    
    // スレッドセーフな操作のためにミューテックスを使用
    std::lock_guard<std::mutex> lock(yaraRulesMutex);
    
    if (this->YrRules == nullptr) {
        LOGERROR("YrScanBuffer: YrRules is NULL");
        return;
    }

    // フェーズ3: より安全なスキャン制御
    // バッファサイズを厳格に制限
    const int MAX_SAFE_BUFFER_SIZE = 8192; // 8KB制限に緩和
    int safeSize = (dwBufferSize > MAX_SAFE_BUFFER_SIZE) ? MAX_SAFE_BUFFER_SIZE : dwBufferSize;

    LOGTRACE("YrScanBuffer: Phase 3 - Enhanced safe scan mode. Va:{:#x} Size:{} (limited from {})", 
            reinterpret_cast<uint64_t>(lpBuffer), safeSize, dwBufferSize);

    // 空のバッファや小さすぎるバッファは処理しない
    if (safeSize <= 16) {
        LOGDEBUG("YrScanBuffer: Buffer too small for meaningful scan, skipping");
        return;
    }

    // メモリ内容の検証 - minマクロの競合問題を回避
    bool hasNonZeroContent = false;
    int checkSize = (512 < safeSize) ? 512 : safeSize;  // std::minの代わりに直接条件式を使用
    
    for (int i = 0; i < checkSize; i++) {
        if (lpBuffer[i] != 0) {
            hasNonZeroContent = true;
            break;
        }
    }
    
    if (!hasNonZeroContent) {
        LOGDEBUG("YrScanBuffer: Buffer contains only zeros in first 512 bytes, skipping");
        return;
    }

    // C++例外処理だけを使用してスキャン
    try {
        // 最適化されたスキャン設定
        int timeout = 20; // タイムアウト値を緩和
        int flags = SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_FAST_MODE;
        
        LOGTRACE("YrScanBuffer: Starting enhanced scan with timeout {}s", timeout);
        
        // SEH処理はScanMemWithSEH内部に閉じ込める（C++例外処理との分離）
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

YaraManager::~YaraManager() {
    // スレッドセーフなクリーンアップ
    std::lock_guard<std::mutex> lock(yaraRulesMutex);
    
    if (this->YrRules != nullptr) {
        yr_rules_destroy(this->YrRules);
        this->YrRules = nullptr;
    }
    if (this->YrCompiler != nullptr) {
        yr_compiler_destroy(this->YrCompiler);
        this->YrCompiler = nullptr;
    }
    if (this->YrScanner != nullptr) {
        yr_scanner_destroy(this->YrScanner);
        this->YrScanner = nullptr;
    }
    
    if (m_initialized) {
        int res = yr_finalize();
        if (res != ERROR_SUCCESS) {
            LOGERROR("Failed to finalize libyara. Error:0x{:x}", res);
        }
        LOGTRACE("Finalized YaraManager");
        m_initialized = false;
    }
}

}  // namespace yama