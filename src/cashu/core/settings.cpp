// NUTSHELL COMPATIBILITY: cashu/core/settings.py
// Configuration management and environment variable handling implementation

#include "cashu/core/settings.hpp"
#include <boost/multiprecision/cpp_int.hpp>

#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <cctype>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::settings {

// Global settings instance
std::unique_ptr<Settings> settings = nullptr;

// Environment variables cache
static unordered_map<string, string> env_cache;

// Helper functions for environment variable conversion
template<>
bool EnvironmentLoader::get_env<bool>(const string& key, const bool& default_value) {
    const char* env_val = getenv(key.c_str());
    if (!env_val) {
        auto it = env_cache.find(key);
        if (it != env_cache.end()) {
            env_val = it->second.c_str();
        } else {
            return default_value;
        }
    }
    
    string val = env_val;
    transform(val.begin(), val.end(), val.begin(), ::tolower);
    return val == "true" || val == "1" || val == "yes" || val == "on";
}

template<>
int EnvironmentLoader::get_env<int>(const string& key, const int& default_value) {
    const char* env_val = getenv(key.c_str());
    if (!env_val) {
        auto it = env_cache.find(key);
        if (it != env_cache.end()) {
            env_val = it->second.c_str();
        } else {
            return default_value;
        }
    }
    
    try {
        return stoi(env_val);
    } catch (const exception&) {
        return default_value;
    }
}

template<>
double EnvironmentLoader::get_env<double>(const string& key, const double& default_value) {
    const char* env_val = getenv(key.c_str());
    if (!env_val) {
        auto it = env_cache.find(key);
        if (it != env_cache.end()) {
            env_val = it->second.c_str();
        } else {
            return default_value;
        }
    }
    
    try {
        return stod(env_val);
    } catch (const exception&) {
        return default_value;
    }
}

template<>
string EnvironmentLoader::get_env<string>(const string& key, const string& default_value) {
    const char* env_val = getenv(key.c_str());
    if (!env_val) {
        auto it = env_cache.find(key);
        if (it != env_cache.end()) {
            return it->second;
        } else {
            return default_value;
        }
    }
    return string(env_val);
}

// EnvironmentLoader implementation
string EnvironmentLoader::find_env_file() {
    // Check current directory first
    string env_file = ".env";
    if (filesystem::exists(env_file)) {
        return env_file;
    }
    
    // Check ~/.cashu/.env
    const char* home = getenv("HOME");
    if (home) {
        string home_env = string(home) + "/.cashu/.env";
        if (filesystem::exists(home_env)) {
            return home_env;
        }
    }
    
    return "";
}

void EnvironmentLoader::load_env_file(const string& env_file) {
    if (env_file.empty() || !filesystem::exists(env_file)) {
        return;
    }
    
    ifstream file(env_file);
    string line;
    
    while (getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Find equals sign
        size_t eq_pos = line.find('=');
        if (eq_pos == string::npos) {
            continue;
        }
        
        string key = line.substr(0, eq_pos);
        string value = line.substr(eq_pos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        // Remove quotes if present
        if (value.size() >= 2 && 
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }
        
        env_cache[key] = value;
    }
}

// CashuSettings implementation
CashuSettings::CashuSettings() 
    : lightning_fee_percent(1.0)
    , lightning_reserve_fee_min(2000)
    , max_order(64)
{
    load_env_settings();
}

void CashuSettings::load_env_settings() {
    env_file = EnvironmentLoader::find_env_file();
    EnvironmentLoader::load_env_file(env_file);
    
    lightning_fee_percent = EnvironmentLoader::get_env("LIGHTNING_FEE_PERCENT", lightning_fee_percent);
    lightning_reserve_fee_min = EnvironmentLoader::get_env("LIGHTNING_RESERVE_FEE_MIN", lightning_reserve_fee_min);
    max_order = EnvironmentLoader::get_env("MAX_ORDER", max_order);
}

// EnvSettings implementation
EnvSettings::EnvSettings() 
    : debug(false)
    , log_level("INFO")
    , debug_profiling(false)
    , debug_mint_only_deprecated(false)
    , db_connection_pool(true)
{
    const char* home = getenv("HOME");
    cashu_dir = home ? string(home) + "/.cashu" : ".cashu";
    
    debug = EnvironmentLoader::get_env("DEBUG", debug);
    log_level = EnvironmentLoader::get_env("LOG_LEVEL", log_level);
    cashu_dir = EnvironmentLoader::get_env("CASHU_DIR", cashu_dir);
    debug_profiling = EnvironmentLoader::get_env("DEBUG_PROFILING", debug_profiling);
    debug_mint_only_deprecated = EnvironmentLoader::get_env("DEBUG_MINT_ONLY_DEPRECATED", debug_mint_only_deprecated);
    db_connection_pool = EnvironmentLoader::get_env("DB_CONNECTION_POOL", db_connection_pool);
    
    string db_backup = EnvironmentLoader::get_env("DB_BACKUP_PATH", string(""));
    if (!db_backup.empty()) {
        db_backup_path = db_backup;
    }
}

// MintSettings implementation
MintSettings::MintSettings()
    : mint_derivation_path("m/0'/0'/0'")
    , mint_listen_host("127.0.0.1")
    , mint_listen_port(3338)
    , mint_database("data/mint")
    , mint_test_database("test_data/test_mint")
    , mint_max_secret_length(1024)
    , mint_input_fee_ppk(0)
    , mint_disable_melt_on_error(false)
    , mint_regular_tasks_interval_seconds(3600)
{
    string private_key = EnvironmentLoader::get_env("MINT_PRIVATE_KEY", string(""));
    if (!private_key.empty()) {
        mint_private_key = private_key;
    }
    
    string decryption_key = EnvironmentLoader::get_env("MINT_SEED_DECRYPTION_KEY", string(""));
    if (!decryption_key.empty()) {
        mint_seed_decryption_key = decryption_key;
    }
    
    mint_derivation_path = EnvironmentLoader::get_env("MINT_DERIVATION_PATH", mint_derivation_path);
    mint_listen_host = EnvironmentLoader::get_env("MINT_LISTEN_HOST", mint_listen_host);
    mint_listen_port = EnvironmentLoader::get_env("MINT_LISTEN_PORT", mint_listen_port);
    mint_database = EnvironmentLoader::get_env("MINT_DATABASE", mint_database);
    mint_test_database = EnvironmentLoader::get_env("MINT_TEST_DATABASE", mint_test_database);
    mint_max_secret_length = EnvironmentLoader::get_env("MINT_MAX_SECRET_LENGTH", mint_max_secret_length);
    mint_input_fee_ppk = EnvironmentLoader::get_env("MINT_INPUT_FEE_PPK", mint_input_fee_ppk);
    mint_disable_melt_on_error = EnvironmentLoader::get_env("MINT_DISABLE_MELT_ON_ERROR", mint_disable_melt_on_error);
    mint_regular_tasks_interval_seconds = EnvironmentLoader::get_env("MINT_REGULAR_TASKS_INTERVAL_SECONDS", mint_regular_tasks_interval_seconds);
}

// MintWatchdogSettings implementation
MintWatchdogSettings::MintWatchdogSettings()
    : mint_watchdog_enabled(false)
    , mint_watchdog_balance_check_interval_seconds(60.0)
    , mint_watchdog_ignore_mismatch(false)
{
    mint_watchdog_enabled = EnvironmentLoader::get_env("MINT_WATCHDOG_ENABLED", mint_watchdog_enabled);
    mint_watchdog_balance_check_interval_seconds = EnvironmentLoader::get_env("MINT_WATCHDOG_BALANCE_CHECK_INTERVAL_SECONDS", mint_watchdog_balance_check_interval_seconds);
    mint_watchdog_ignore_mismatch = EnvironmentLoader::get_env("MINT_WATCHDOG_IGNORE_MISMATCH", mint_watchdog_ignore_mismatch);
}

// MintBackends implementation
MintBackends::MintBackends()
    : mint_lnd_rest_cert_verify(true)
    , mint_lnd_enable_mpp(true)
    , mint_clnrest_enable_mpp(true)
{
    mint_lightning_backend = EnvironmentLoader::get_env("MINT_LIGHTNING_BACKEND", string(""));
    mint_backend_bolt11_sat = EnvironmentLoader::get_env("MINT_BACKEND_BOLT11_SAT", string(""));
    mint_backend_bolt11_msat = EnvironmentLoader::get_env("MINT_BACKEND_BOLT11_MSAT", string(""));
    mint_backend_bolt11_usd = EnvironmentLoader::get_env("MINT_BACKEND_BOLT11_USD", string(""));
    mint_backend_bolt11_eur = EnvironmentLoader::get_env("MINT_BACKEND_BOLT11_EUR", string(""));
    
    string lnbits_endpoint = EnvironmentLoader::get_env("MINT_LNBITS_ENDPOINT", string(""));
    if (!lnbits_endpoint.empty()) {
        mint_lnbits_endpoint = lnbits_endpoint;
    }
    
    string lnbits_key = EnvironmentLoader::get_env("MINT_LNBITS_KEY", string(""));
    if (!lnbits_key.empty()) {
        mint_lnbits_key = lnbits_key;
    }
    
    string strike_key = EnvironmentLoader::get_env("MINT_STRIKE_KEY", string(""));
    if (!strike_key.empty()) {
        mint_strike_key = strike_key;
    }
    
    string blink_key = EnvironmentLoader::get_env("MINT_BLINK_KEY", string(""));
    if (!blink_key.empty()) {
        mint_blink_key = blink_key;
    }
    
    // LND REST settings
    string lnd_rest_endpoint = EnvironmentLoader::get_env("MINT_LND_REST_ENDPOINT", string(""));
    if (!lnd_rest_endpoint.empty()) {
        mint_lnd_rest_endpoint = lnd_rest_endpoint;
    }
    
    string lnd_rest_cert = EnvironmentLoader::get_env("MINT_LND_REST_CERT", string(""));
    if (!lnd_rest_cert.empty()) {
        mint_lnd_rest_cert = lnd_rest_cert;
    }
    
    string lnd_rest_macaroon = EnvironmentLoader::get_env("MINT_LND_REST_MACAROON", string(""));
    if (!lnd_rest_macaroon.empty()) {
        mint_lnd_rest_macaroon = lnd_rest_macaroon;
    }
    
    string lnd_rest_admin_macaroon = EnvironmentLoader::get_env("MINT_LND_REST_ADMIN_MACAROON", string(""));
    if (!lnd_rest_admin_macaroon.empty()) {
        mint_lnd_rest_admin_macaroon = lnd_rest_admin_macaroon;
    }
    
    string lnd_rest_invoice_macaroon = EnvironmentLoader::get_env("MINT_LND_REST_INVOICE_MACAROON", string(""));
    if (!lnd_rest_invoice_macaroon.empty()) {
        mint_lnd_rest_invoice_macaroon = lnd_rest_invoice_macaroon;
    }
    
    mint_lnd_rest_cert_verify = EnvironmentLoader::get_env("MINT_LND_REST_CERT_VERIFY", true);
    mint_lnd_enable_mpp = EnvironmentLoader::get_env("MINT_LND_ENABLE_MPP", true);
    
    // CLN REST settings
    string clnrest_url = EnvironmentLoader::get_env("MINT_CLNREST_URL", string(""));
    if (!clnrest_url.empty()) {
        mint_clnrest_url = clnrest_url;
    }
    
    string clnrest_cert = EnvironmentLoader::get_env("MINT_CLNREST_CERT", string(""));
    if (!clnrest_cert.empty()) {
        mint_clnrest_cert = clnrest_cert;
    }
    
    string clnrest_rune = EnvironmentLoader::get_env("MINT_CLNREST_RUNE", string(""));
    if (!clnrest_rune.empty()) {
        mint_clnrest_rune = clnrest_rune;
    }
    
    mint_clnrest_enable_mpp = EnvironmentLoader::get_env("MINT_CLNREST_ENABLE_MPP", true);
}

// MintLimits implementation
MintLimits::MintLimits()
    : mint_rate_limit(false)
    , mint_global_rate_limit_per_minute(60)
    , mint_transaction_rate_limit_per_minute(20)
    , mint_max_request_length(1000)
    , mint_peg_out_only(false)
    , mint_bolt11_disable_mint(false)
    , mint_bolt11_disable_melt(false)
    , mint_websocket_read_timeout(600)
{
    mint_rate_limit = EnvironmentLoader::get_env("MINT_RATE_LIMIT", mint_rate_limit);
    mint_global_rate_limit_per_minute = EnvironmentLoader::get_env("MINT_GLOBAL_RATE_LIMIT_PER_MINUTE", mint_global_rate_limit_per_minute);
    mint_transaction_rate_limit_per_minute = EnvironmentLoader::get_env("MINT_TRANSACTION_RATE_LIMIT_PER_MINUTE", mint_transaction_rate_limit_per_minute);
    mint_max_request_length = EnvironmentLoader::get_env("MINT_MAX_REQUEST_LENGTH", mint_max_request_length);
    mint_peg_out_only = EnvironmentLoader::get_env("MINT_PEG_OUT_ONLY", mint_peg_out_only);
    mint_bolt11_disable_mint = EnvironmentLoader::get_env("MINT_BOLT11_DISABLE_MINT", mint_bolt11_disable_mint);
    mint_bolt11_disable_melt = EnvironmentLoader::get_env("MINT_BOLT11_DISABLE_MELT", mint_bolt11_disable_melt);
    mint_websocket_read_timeout = EnvironmentLoader::get_env("MINT_WEBSOCKET_READ_TIMEOUT", mint_websocket_read_timeout);
}

// WalletSettings implementation
WalletSettings::WalletSettings()
    : tor(false)
    , socks_port(9050)
    , mint_host("8333.space")
    , mint_port(3338)
    , wallet_name("wallet")
    , wallet_unit("sat")
    , wallet_use_deprecated_h2c(false)
    , api_port(4448)
    , api_host("127.0.0.1")
    , locktime_delta_seconds(86400)
    , proofs_batch_size(200)
    , wallet_target_amount_count(3)
{
    tor = EnvironmentLoader::get_env("TOR", tor);
    socks_port = EnvironmentLoader::get_env("SOCKS_PORT", socks_port);
    mint_host = EnvironmentLoader::get_env("MINT_HOST", mint_host);
    mint_port = EnvironmentLoader::get_env("MINT_PORT", mint_port);
    wallet_name = EnvironmentLoader::get_env("WALLET_NAME", wallet_name);
    wallet_unit = EnvironmentLoader::get_env("WALLET_UNIT", wallet_unit);
    wallet_use_deprecated_h2c = EnvironmentLoader::get_env("WALLET_USE_DEPRECATED_H2C", wallet_use_deprecated_h2c);
    api_port = EnvironmentLoader::get_env("API_PORT", api_port);
    api_host = EnvironmentLoader::get_env("API_HOST", api_host);
    locktime_delta_seconds = EnvironmentLoader::get_env("LOCKTIME_DELTA_SECONDS", locktime_delta_seconds);
    proofs_batch_size = EnvironmentLoader::get_env("PROOFS_BATCH_SIZE", proofs_batch_size);
    wallet_target_amount_count = EnvironmentLoader::get_env("WALLET_TARGET_AMOUNT_COUNT", wallet_target_amount_count);
    
    string mint_url_env = EnvironmentLoader::get_env("MINT_URL", string(""));
    if (!mint_url_env.empty()) {
        mint_url = mint_url_env;
    }
    
    string socks_host_env = EnvironmentLoader::get_env("SOCKS_HOST", string(""));
    if (!socks_host_env.empty()) {
        socks_host = socks_host_env;
    }
    
    string socks_proxy_env = EnvironmentLoader::get_env("SOCKS_PROXY", string(""));
    if (!socks_proxy_env.empty()) {
        socks_proxy = socks_proxy_env;
    }
    
    string http_proxy_env = EnvironmentLoader::get_env("HTTP_PROXY", string(""));
    if (!http_proxy_env.empty()) {
        http_proxy = http_proxy_env;
    }
}

// AuthSettings implementation
AuthSettings::AuthSettings()
    : mint_auth_database("data/mint")
    , mint_require_auth(false)
    , mint_auth_oicd_client_id("cashu-client")
    , mint_auth_rate_limit_per_minute(5)
    , mint_auth_max_blind_tokens(100)
{
    mint_auth_database = EnvironmentLoader::get_env("MINT_AUTH_DATABASE", mint_auth_database);
    mint_require_auth = EnvironmentLoader::get_env("MINT_REQUIRE_AUTH", mint_require_auth);
    mint_auth_oicd_client_id = EnvironmentLoader::get_env("MINT_AUTH_OICD_CLIENT_ID", mint_auth_oicd_client_id);
    mint_auth_rate_limit_per_minute = EnvironmentLoader::get_env("MINT_AUTH_RATE_LIMIT_PER_MINUTE", mint_auth_rate_limit_per_minute);
    mint_auth_max_blind_tokens = EnvironmentLoader::get_env("MINT_AUTH_MAX_BLIND_TOKENS", mint_auth_max_blind_tokens);
    
    string discovery_url = EnvironmentLoader::get_env("MINT_AUTH_OICD_DISCOVERY_URL", string(""));
    if (!discovery_url.empty()) {
        mint_auth_oicd_discovery_url = discovery_url;
    }
}

// MintRedisCache implementation
MintRedisCache::MintRedisCache()
    : mint_redis_cache_enabled(false)
    , mint_redis_cache_ttl(60 * 60 * 24 * 7)  // 1 week default
{
    mint_redis_cache_enabled = EnvironmentLoader::get_env("MINT_REDIS_CACHE_ENABLED", mint_redis_cache_enabled);
    mint_redis_cache_ttl = EnvironmentLoader::get_env("MINT_REDIS_CACHE_TTL", mint_redis_cache_ttl.value());
    
    string cache_url = EnvironmentLoader::get_env("MINT_REDIS_CACHE_URL", string(""));
    if (!cache_url.empty()) {
        mint_redis_cache_url = cache_url;
    }
}

// WalletDeprecationFlags implementation
WalletDeprecationFlags::WalletDeprecationFlags()
    : wallet_inactivate_base64_keysets(true)
{
    wallet_inactivate_base64_keysets = EnvironmentLoader::get_env("WALLET_INACTIVATE_BASE64_KEYSETS", wallet_inactivate_base64_keysets);
}

// LndRPCFundingSource implementation
LndRPCFundingSource::LndRPCFundingSource()
{
    string lnd_rpc_endpoint = EnvironmentLoader::get_env("MINT_LND_RPC_ENDPOINT", string(""));
    if (!lnd_rpc_endpoint.empty()) {
        mint_lnd_rpc_endpoint = lnd_rpc_endpoint;
    }
    
    string lnd_rpc_cert = EnvironmentLoader::get_env("MINT_LND_RPC_CERT", string(""));
    if (!lnd_rpc_cert.empty()) {
        mint_lnd_rpc_cert = lnd_rpc_cert;
    }
    
    string lnd_rpc_macaroon = EnvironmentLoader::get_env("MINT_LND_RPC_MACAROON", string(""));
    if (!lnd_rpc_macaroon.empty()) {
        mint_lnd_rpc_macaroon = lnd_rpc_macaroon;
    }
}

// Settings implementation
Settings::Settings() : version(VERSION) {
    // Constructor initializes all parent classes
}

void Settings::initialize() {
    startup_settings_tasks();
}

void Settings::reload() {
    // Reload environment file
    env_file = EnvironmentLoader::find_env_file();
    EnvironmentLoader::load_env_file(env_file);
    
    // Reinitialize all settings
    load_env_settings();
    startup_settings_tasks();
}

Settings Settings::copy() const {
    return *this;
}

void Settings::startup_settings_tasks() {
    // Replace ~ with home directory in cashu_dir
    const char* home = getenv("HOME");
    if (home) {
        string home_dir = home;
        size_t pos = EnvSettings::cashu_dir.find("~");
        if (pos != string::npos) {
            EnvSettings::cashu_dir.replace(pos, 1, home_dir);
        }
    }
    
    // Set mint_url if only mint_host is set
    if (!WalletSettings::mint_url.has_value()) {
        if (WalletSettings::mint_host == "localhost" || WalletSettings::mint_host == "127.0.0.1") {
            WalletSettings::mint_url = "http://" + WalletSettings::mint_host + ":" + to_string(WalletSettings::mint_port);
        } else {
            WalletSettings::mint_url = "https://" + WalletSettings::mint_host + ":" + to_string(WalletSettings::mint_port);
        }
    }
    
    apply_backward_compatibility();
    validate_settings();
}

void Settings::apply_backward_compatibility() {
    // Backwards compatibility: set socks_proxy from socks_host and socks_port
    if (WalletSettings::socks_host.has_value() && WalletSettings::socks_port > 0) {
        WalletSettings::socks_proxy = "socks5://" + WalletSettings::socks_host.value() + ":" + to_string(WalletSettings::socks_port);
    }
    
    // Backwards compatibility: set mint_backend_bolt11_sat from mint_lightning_backend
    if (!MintBackends::mint_lightning_backend.empty()) {
        MintBackends::mint_backend_bolt11_sat = MintBackends::mint_lightning_backend;
    }
    
    // Backwards compatibility: mint_peg_out_only to mint_bolt11_disable_mint
    if (MintLimits::mint_peg_out_only) {
        MintLimits::mint_bolt11_disable_mint = true;
    }
}

void Settings::validate_settings() {
    // Validate fee settings
    if (MintSettings::mint_input_fee_ppk < 0) {
        throw runtime_error("Input fee must be non-negative.");
    }
    
    // Validate timeout settings
    if (MintSettings::mint_regular_tasks_interval_seconds <= 0) {
        throw runtime_error("Regular tasks interval must be positive.");
    }
    
    if (MintLimits::mint_websocket_read_timeout <= 0) {
        throw runtime_error("WebSocket read timeout must be positive.");
    }
}

// Global functions
void initialize_settings() {
    if (!settings) {
        settings = make_unique<Settings>();
        settings->initialize();
    }
}

Settings& get_settings() {
    if (!settings) {
        initialize_settings();
    }
    return *settings;
}

} // namespace cashu::core::settings