#ifndef SRC_YARAMANAGER_HPP
#define SRC_YARAMANAGER_HPP

#include <yara.h>
#include <unordered_set>
#include <string>
#include "logger.h"

// Windows min/maxマクロを無効化
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace yama {
static const char* sample_rule =
    "rule mz_header {"
    "  condition:"
    "    uint16(0) == 0x5A4D "
    "}";

// YARAルール検出結果を格納する構造体
struct YrResult {
    bool result;
    std::unordered_set<std::string /*rule_name*/> *matchRuleSet = nullptr;
    
    // 安全な解放のためのデストラクタ追加
    ~YrResult() {
        if (matchRuleSet != nullptr) {
            delete matchRuleSet;
            matchRuleSet = nullptr;
        }
    }
};

class YaraManager {
   private:
    YR_COMPILER* YrCompiler;
    YR_SCANNER* YrScanner;
    YR_RULES* YrRules;
    bool m_initialized; // 変数名を変更

    // SEH処理を分離した内部ヘルパーメソッド
    int ScanMemWithSEH(YR_RULES* rules, const unsigned char* buffer, 
                      int size, int flags, YR_CALLBACK_FUNC callback, 
                      void* userData, int timeout);
                      
    // ルール構文の基本検証
    bool IsValidRule(const char* strRule);

   public:
    YaraManager();
    static int YrScanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data,
                              void* user_data);
    
    bool YrCreateScanner();
    bool YrAddRuleFromString(const char* strRule);
    void YrScanBuffer(const unsigned char* lpBuffer, int dwBufferSize, void* lpUserData);
    
    // 初期化状態を確認するメソッド
    bool IsInitialized() const { return m_initialized; }
    
    // YARAルールが読み込まれているか確認するメソッド
    bool HasRules() const { return YrRules != nullptr; }

    ~YaraManager();
};

}  // namespace yama
#endif  // SRC_YARAMANAGER_HPP