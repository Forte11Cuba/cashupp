#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/settings.py
// Configuration management and environment variable handling

#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace cashu::core::settings {

// Version constant matching nutshell
constexpr const char* VERSION = "0.17.0";

// Forward declarations
class CashuSettings;
class Settings;

// Global settings instance (singleton pattern)
extern std::unique_ptr<Settings> settings;

/**
 * Environment file utilities
 */
class EnvironmentLoader {
public:
    /**
     * Find and load environment file (.env)
     * Searches in current directory first, then ~/.cashu/.env
     */
    static std::string find_env_file();
    
    /**
     * Load environment variables from file
     */
    static void load_env_file(const std::string& env_file);
    
    /**
     * Get environment variable with default
     */
    template<typename T>
    static T get_env(const std::string& key, const T& default_value);
};

/**
 * Base settings class matching CashuSettings in nutshell
 */
class CashuSettings {
public:
    CashuSettings();
    virtual ~CashuSettings() = default;
    
    // Core settings
    std::string env_file;
    double lightning_fee_percent;
    int lightning_reserve_fee_min;
    int max_order;
    
protected:
    void load_env_settings();
};

/**
 * Environment and debug settings
 */
class EnvSettings : public virtual CashuSettings {
public:
    EnvSettings();
    
    bool debug;
    std::string log_level;
    std::string cashu_dir;
    bool debug_profiling;
    bool debug_mint_only_deprecated;
    std::optional<std::string> db_backup_path;
    bool db_connection_pool;
};

/**
 * Mint-specific settings
 */
class MintSettings : public virtual CashuSettings {
public:
    MintSettings();
    
    // Keys and derivation
    std::optional<std::string> mint_private_key;
    std::optional<std::string> mint_seed_decryption_key;
    std::string mint_derivation_path;
    std::vector<std::string> mint_derivation_path_list;
    
    // Network settings
    std::string mint_listen_host;
    int mint_listen_port;
    
    // Database settings
    std::string mint_database;
    std::string mint_test_database;
    int mint_max_secret_length;
    
    // Fee settings
    int mint_input_fee_ppk;
    bool mint_disable_melt_on_error;
    
    // Task intervals
    int mint_regular_tasks_interval_seconds;
};

/**
 * Mint watchdog settings
 */
class MintWatchdogSettings : public virtual MintSettings {
public:
    MintWatchdogSettings();
    
    bool mint_watchdog_enabled;
    double mint_watchdog_balance_check_interval_seconds;
    bool mint_watchdog_ignore_mismatch;
};

/**
 * Lightning backend settings
 */
class MintBackends : public virtual MintSettings {
public:
    MintBackends();
    
    // Lightning backends
    std::string mint_lightning_backend;  // deprecated
    std::string mint_backend_bolt11_sat;
    std::string mint_backend_bolt11_msat;
    std::string mint_backend_bolt11_usd;
    std::string mint_backend_bolt11_eur;
    
    // LNbits settings
    std::optional<std::string> mint_lnbits_endpoint;
    std::optional<std::string> mint_lnbits_key;
    
    // LND REST settings
    std::optional<std::string> mint_lnd_rest_endpoint;
    std::optional<std::string> mint_lnd_rest_cert;
    std::optional<std::string> mint_lnd_rest_macaroon;
    std::optional<std::string> mint_lnd_rest_admin_macaroon;
    std::optional<std::string> mint_lnd_rest_invoice_macaroon;
    bool mint_lnd_rest_cert_verify;
    bool mint_lnd_enable_mpp;
    
    // CLN REST settings
    std::optional<std::string> mint_clnrest_url;
    std::optional<std::string> mint_clnrest_cert;
    std::optional<std::string> mint_clnrest_rune;
    bool mint_clnrest_enable_mpp;
    
    // Other Lightning backends
    std::optional<std::string> mint_strike_key;
    std::optional<std::string> mint_blink_key;
};

/**
 * Rate limiting and security settings
 */
class MintLimits : public virtual MintSettings {
public:
    MintLimits();
    
    // Rate limiting
    bool mint_rate_limit;
    int mint_global_rate_limit_per_minute;
    int mint_transaction_rate_limit_per_minute;
    int mint_max_request_length;
    
    // Operation limits
    bool mint_peg_out_only;  // deprecated
    bool mint_bolt11_disable_mint;
    bool mint_bolt11_disable_melt;
    
    // Amount limits
    std::optional<int> mint_max_peg_in;  // deprecated
    std::optional<int> mint_max_peg_out;  // deprecated
    std::optional<int> mint_max_mint_bolt11_sat;
    std::optional<int> mint_max_melt_bolt11_sat;
    std::optional<int> mint_max_balance;
    
    // WebSocket settings
    int mint_websocket_read_timeout;
};

/**
 * Wallet settings
 */
class WalletSettings : public virtual CashuSettings {
public:
    WalletSettings();
    
    // Networking
    bool tor;
    std::optional<std::string> socks_host;  // deprecated
    int socks_port;  // deprecated
    std::optional<std::string> socks_proxy;
    std::optional<std::string> http_proxy;
    
    // Mint connection
    std::optional<std::string> mint_url;
    std::string mint_host;
    int mint_port;
    
    // Wallet settings
    std::string wallet_name;
    std::string wallet_unit;
    bool wallet_use_deprecated_h2c;
    
    // API settings
    int api_port;
    std::string api_host;
    
    // Timing settings
    int locktime_delta_seconds;
    int proofs_batch_size;
    int wallet_target_amount_count;
};

/**
 * Authentication settings
 */
class AuthSettings : public virtual MintSettings {
public:
    AuthSettings();
    
    std::string mint_auth_database;
    bool mint_require_auth;
    std::optional<std::string> mint_auth_oicd_discovery_url;
    std::string mint_auth_oicd_client_id;
    int mint_auth_rate_limit_per_minute;
    int mint_auth_max_blind_tokens;
};

/**
 * Redis cache settings
 */
class MintRedisCache : public virtual MintSettings {
public:
    MintRedisCache();
    
    bool mint_redis_cache_enabled;
    std::optional<std::string> mint_redis_cache_url;
    std::optional<int> mint_redis_cache_ttl;  // Default: 1 week
};

/**
 * Wallet deprecation flags
 */
class WalletDeprecationFlags : public virtual CashuSettings {
public:
    WalletDeprecationFlags();
    
    bool wallet_inactivate_base64_keysets;
};

/**
 * LND RPC funding source settings
 */
class LndRPCFundingSource : public virtual MintSettings {
public:
    LndRPCFundingSource();
    
    std::optional<std::string> mint_lnd_rpc_endpoint;
    std::optional<std::string> mint_lnd_rpc_cert;
    std::optional<std::string> mint_lnd_rpc_macaroon;
};

/**
 * Main settings class combining all settings types
 * Matches Settings class in nutshell which inherits from all settings classes
 */
class Settings : 
    public EnvSettings,
    public MintWatchdogSettings,
    public MintBackends,
    public MintLimits,
    public WalletSettings,
    public AuthSettings,
    public MintRedisCache,
    public WalletDeprecationFlags,
    public LndRPCFundingSource
{
public:
    Settings();
    ~Settings() = default;
    
    // Version information
    std::string version;
    
    /**
     * Initialize settings from environment
     * Should be called once at startup
     */
    void initialize();
    
    /**
     * Reload settings from environment
     */
    void reload();
    
    /**
     * Get a copy of current settings
     */
    Settings copy() const;
    
private:
    void startup_settings_tasks();
    void apply_backward_compatibility();
    void validate_settings();
};

/**
 * Initialize global settings instance
 * Call this once at application startup
 */
void initialize_settings();

/**
 * Get global settings instance
 */
Settings& get_settings();

} // namespace cashu::core::settings