#pragma once

// NUTSHELL COMPATIBILITY: cashu/mint/crud.py + cashu/wallet/crud.py  
// Database models and schemas for 100% nutshell compatibility
// Reference: Complete database schema analysis from nutshell codebase

#include "cashu/core/base.hpp"
#include "cashu/core/settings.hpp"
#include "cashu/core/errors.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <chrono>
#include <nlohmann/json.hpp>

namespace cashu::core::models {

using namespace boost::multiprecision;
using json = nlohmann::json;
using timestamp_t = std::chrono::system_clock::time_point;

//=============================================================================
// Core Enums and Types
//=============================================================================

/**
 * Currency units supported by the mint
 * Must match nutshell Unit enum exactly
 */
enum class Unit {
    sat = 0,
    msat = 1, 
    usd = 2,
    eur = 3,
    btc = 4,
    auth = 999  // Special auth tokens
};

/**
 * Payment methods for lightning integration
 */
enum class Method {
    bolt11 = 0
};

/**
 * Proof spending states
 */
enum class ProofSpentState {
    unspent,    // "UNSPENT" 
    spent,      // "SPENT"
    pending     // "PENDING"
};

/**
 * Mint quote states (Lightning invoice payment)
 */
enum class MintQuoteState {
    unpaid,     // "UNPAID"
    paid,       // "PAID" 
    pending,    // "PENDING"
    issued      // "ISSUED"
};

/**
 * Melt quote states (Lightning payment)
 */
enum class MeltQuoteState {
    unpaid,     // "UNPAID"
    pending,    // "PENDING"
    paid        // "PAID"
};

//=============================================================================
// Database Version Management
//=============================================================================

/**
 * Database migration version tracking
 * Table: dbversions
 */
struct DBVersion {
    std::string db;          // Database name/type
    int version;             // Current schema version
    
    // JSON serialization
    json to_json() const;
    static DBVersion from_json(const json& j);
};

//=============================================================================
// Mint Database Models  
//=============================================================================

/**
 * Mint keysets for different epochs and mints
 * Table: keysets
 */
struct MintKeyset {
    std::string id;                              // Keyset identifier
    std::optional<std::string> derivation_path;  // BIP32 derivation path
    std::optional<std::string> seed;             // Private seed (unencrypted)
    std::optional<std::string> encrypted_seed;   // Encrypted private seed
    std::optional<std::string> seed_encryption_method; // Encryption method
    timestamp_t valid_from;                      // Keyset validity start
    timestamp_t valid_to;                        // Keyset validity end
    timestamp_t first_seen;                      // When first encountered
    bool active = true;                          // Whether keyset is active
    std::optional<std::string> version;         // Software version
    std::string unit;                           // Currency unit
    std::optional<int> input_fee_ppk;           // Input fee per thousand
    std::string amounts;                        // JSON array of supported amounts
    cpp_int balance = 0;                        // Current balance
    cpp_int fees_paid = 0;                      // Total fees paid
    
    // JSON serialization
    json to_json() const;
    static MintKeyset from_json(const json& j);
};

/**
 * Public keys for each keyset amount
 * Table: mint_pubkeys
 */
struct MintPubkey {
    std::string id;                 // Keyset ID reference
    cpp_int amount;                 // Amount denomination
    std::string pubkey;             // Public key hex
    
    // JSON serialization
    json to_json() const;
    static MintPubkey from_json(const json& j);
};

/**
 * Mint promises (blinded signatures)
 * Table: promises
 */
struct Promise {
    cpp_int amount;                             // Promise amount
    std::optional<std::string> id;              // Keyset ID
    std::string b_;                             // Blinded message (B_)
    std::string c_;                             // Blinded signature (C_)
    std::optional<std::string> dleq_e;          // DLEQ proof e component
    std::optional<std::string> dleq_s;          // DLEQ proof s component
    std::optional<timestamp_t> created;        // Creation timestamp
    std::optional<std::string> mint_quote;     // Associated mint quote
    std::optional<std::string> swap_id;        // Swap operation ID
    
    // JSON serialization
    json to_json() const;
    static Promise from_json(const json& j);
};

/**
 * Spent proofs tracking
 * Table: proofs_used
 */
struct ProofUsed {
    cpp_int amount;                             // Proof amount
    std::optional<std::string> id;              // Keyset ID
    std::string c;                              // Unblinded signature
    std::string secret;                         // Proof secret
    std::optional<std::string> y;               // Hash-to-curve(secret) Y point
    std::optional<std::string> witness;         // Spending witness (P2PK, HTLC, etc.)
    std::optional<timestamp_t> created;        // When proof was created
    std::optional<std::string> melt_quote;     // Associated melt quote
    
    // JSON serialization
    json to_json() const;
    static ProofUsed from_json(const json& j);
};

/**
 * Proofs awaiting confirmation
 * Table: proofs_pending
 */
struct ProofPending {
    cpp_int amount;                             // Proof amount
    std::optional<std::string> id;              // Keyset ID
    std::string c;                              // Unblinded signature
    std::string secret;                         // Proof secret
    std::optional<std::string> y;               // Hash-to-curve(secret) Y point
    std::optional<std::string> witness;         // Spending witness
    timestamp_t created;                        // Creation timestamp (default NOW())
    std::optional<std::string> melt_quote;     // Associated melt quote
    
    // JSON serialization
    json to_json() const;
    static ProofPending from_json(const json& j);
};

/**
 * Lightning invoice mint quotes
 * Table: mint_quotes
 */
struct MintQuote {
    std::string quote;                          // Quote identifier
    std::string method;                         // Payment method (bolt11)
    std::string request;                        // Lightning invoice
    std::string checking_id;                    // Payment checking ID
    std::string unit;                           // Currency unit
    cpp_int amount;                             // Quote amount
    bool paid;                                  // Whether invoice is paid
    bool issued;                                // Whether tokens were issued
    std::optional<timestamp_t> created_time;   // Quote creation time
    std::optional<timestamp_t> paid_time;      // Payment confirmation time
    std::optional<std::string> state;          // Quote state (UNPAID/PAID/PENDING/ISSUED)
    std::optional<std::string> pubkey;         // NUT-20 quote lock pubkey
    
    // JSON serialization
    json to_json() const;
    static MintQuote from_json(const json& j);
};

/**
 * Lightning payment melt quotes
 * Table: melt_quotes
 */
struct MeltQuote {
    std::string quote;                          // Quote identifier
    std::string method;                         // Payment method (bolt11)
    std::string request;                        // Lightning payment request
    std::string checking_id;                    // Payment checking ID
    std::string unit;                           // Currency unit
    cpp_int amount;                             // Input amount
    std::optional<cpp_int> fee_reserve;         // Reserved fee amount
    bool paid;                                  // Whether payment succeeded
    std::optional<timestamp_t> created_time;   // Quote creation time
    std::optional<timestamp_t> paid_time;      // Payment completion time
    std::optional<cpp_int> fee_paid;            // Actual fee paid
    std::optional<std::string> proof;          // Payment proof/preimage
    std::optional<std::string> state;          // Quote state (UNPAID/PENDING/PAID)
    std::optional<std::string> payment_preimage; // Lightning payment preimage
    std::optional<std::string> change;         // JSON change signatures
    std::optional<timestamp_t> expiry;         // Quote expiration
    std::optional<std::string> outputs;        // JSON blinded outputs for change
    
    // JSON serialization
    json to_json() const;
    static MeltQuote from_json(const json& j);
};

/**
 * Balance tracking audit log
 * Table: balance_log
 */
struct BalanceLog {
    std::string unit;                           // Currency unit
    int keyset_balance;                         // Keyset balance snapshot
    int keyset_fees_paid;                       // Fees paid snapshot
    int backend_balance;                        // Backend balance snapshot
    timestamp_t time;                           // Log timestamp (default NOW())
    
    // JSON serialization
    json to_json() const;
    static BalanceLog from_json(const json& j);
};

//=============================================================================
// Wallet Database Models
//=============================================================================

/**
 * Wallet's proof storage
 * Table: proofs (wallet context)
 */
struct WalletProof {
    cpp_int amount;                             // Proof amount
    std::string C;                              // Unblinded signature (note: uppercase C)
    std::string secret;                         // Proof secret
    std::optional<std::string> id;              // Keyset ID
    std::optional<bool> reserved;               // Reserved for sending
    std::optional<std::string> send_id;         // Send operation grouping ID
    std::optional<timestamp_t> time_created;   // Creation timestamp
    std::optional<timestamp_t> time_reserved;  // Reservation timestamp
    std::optional<std::string> derivation_path; // BIP32 derivation path
    std::optional<std::string> dleq;            // DLEQ proof JSON
    std::optional<std::string> mint_id;         // Mint operation ID
    std::optional<std::string> melt_id;         // Melt operation ID
    
    // JSON serialization
    json to_json() const;
    static WalletProof from_json(const json& j);
};

/**
 * Wallet's spent proofs
 * Table: proofs_used (wallet context)
 */
struct WalletProofUsed {
    cpp_int amount;                             // Proof amount
    std::string C;                              // Unblinded signature (note: uppercase C)
    std::string secret;                         // Proof secret
    std::optional<std::string> id;              // Keyset ID
    std::optional<timestamp_t> time_used;      // When proof was spent
    std::optional<std::string> derivation_path; // BIP32 derivation path
    std::optional<std::string> mint_id;         // Mint operation ID
    std::optional<std::string> melt_id;         // Melt operation ID
    
    // JSON serialization
    json to_json() const;
    static WalletProofUsed from_json(const json& j);
};

/**
 * Wallet's keyset storage
 * Table: keysets (wallet context)
 */
struct WalletKeyset {
    std::optional<std::string> id;              // Keyset identifier
    std::optional<std::string> mint_url;        // Mint URL
    timestamp_t valid_from;                     // Validity start (default NOW())
    timestamp_t valid_to;                       // Validity end (default NOW())
    timestamp_t first_seen;                     // First seen timestamp (default NOW())
    bool active = true;                         // Whether keyset is active
    std::optional<std::string> public_keys;     // JSON public keys
    int counter = 0;                            // Derivation counter
    std::optional<std::string> unit;            // Currency unit
    std::optional<int> input_fee_ppk;           // Input fee per thousand
    
    // JSON serialization
    json to_json() const;
    static WalletKeyset from_json(const json& j);
};

/**
 * Lightning invoices (wallet context)
 * Table: invoices
 */
struct Invoice {
    int amount;                                 // Invoice amount
    std::string bolt11;                         // Lightning invoice (renamed from pr)
    std::optional<std::string> id;              // Invoice ID (was hash)
    std::optional<std::string> payment_hash;    // Payment hash
    std::optional<std::string> preimage;        // Payment preimage
    bool paid = false;                          // Payment status
    timestamp_t time_created;                   // Creation time (default NOW())
    timestamp_t time_paid;                      // Payment time (default NOW())
    std::optional<bool> out;                    // Outgoing (TRUE) or incoming (FALSE)
    
    // JSON serialization
    json to_json() const;
    static Invoice from_json(const json& j);
};

/**
 * Wallet seed storage
 * Table: seed
 */
struct Seed {
    std::string seed;                           // Master seed
    std::string mnemonic;                       // BIP39 mnemonic
    
    // JSON serialization
    json to_json() const;
    static Seed from_json(const json& j);
};

/**
 * Wallet mint quotes
 * Table: bolt11_mint_quotes
 */
struct WalletMintQuote {
    std::string quote;                          // Quote identifier (PRIMARY KEY)
    std::string mint;                           // Mint URL
    std::string method;                         // Payment method
    std::string request;                        // Payment request
    std::string checking_id;                    // Checking ID
    std::string unit;                           // Currency unit
    int amount;                                 // Amount
    std::string state;                          // Quote state
    std::optional<int> created_time;            // Creation timestamp
    std::optional<int> paid_time;               // Payment timestamp
    std::optional<int> expiry;                  // Expiry timestamp
    std::optional<std::string> privkey;         // Private key for NUT-20
    
    // JSON serialization
    json to_json() const;
    static WalletMintQuote from_json(const json& j);
};

/**
 * Wallet melt quotes
 * Table: bolt11_melt_quotes
 */
struct WalletMeltQuote {
    std::string quote;                          // Quote identifier (PRIMARY KEY)
    std::string mint;                           // Mint URL
    std::string method;                         // Payment method
    std::string request;                        // Payment request
    std::string checking_id;                    // Checking ID
    std::string unit;                           // Currency unit
    int amount;                                 // Amount
    int fee_reserve;                            // Fee reserve
    std::string state;                          // Quote state
    std::optional<int> created_time;            // Creation timestamp
    std::optional<int> paid_time;               // Payment timestamp
    std::optional<int> fee_paid;                // Actual fee paid
    std::optional<std::string> payment_preimage; // Payment preimage
    std::optional<int> expiry;                  // Expiry timestamp
    std::optional<std::string> change;          // Change signatures JSON
    
    // JSON serialization
    json to_json() const;
    static WalletMeltQuote from_json(const json& j);
};

/**
 * Nostr integration timestamps
 * Table: nostr
 */
struct NostrState {
    std::string type;                           // Operation type
    std::optional<timestamp_t> last;            // Last operation timestamp
    
    // JSON serialization
    json to_json() const;
    static NostrState from_json(const json& j);
};

/**
 * Known mints registry
 * Table: mints
 */
struct Mint {
    std::optional<int> id;                      // Auto-increment ID (PRIMARY KEY)
    std::string url;                            // Mint URL
    std::string info;                           // Mint info JSON
    timestamp_t updated;                        // Last update (default NOW())
    std::optional<std::string> access_token;    // OAuth access token
    std::optional<std::string> refresh_token;   // OAuth refresh token
    std::optional<std::string> username;        // Basic auth username
    std::optional<std::string> password;        // Basic auth password
    
    // JSON serialization
    json to_json() const;
    static Mint from_json(const json& j);
};

//=============================================================================
// Auth Database Models (Multi-user mint extension)
//=============================================================================

/**
 * Authenticated users
 * Table: users
 */
struct User {
    std::string id;                             // User identifier (PRIMARY KEY)
    std::optional<timestamp_t> last_access;    // Last access time
    
    // JSON serialization
    json to_json() const;
    static User from_json(const json& j);
};

//=============================================================================
// Balance Views and Computed Data
//=============================================================================

/**
 * Balance calculation result (from database views)
 */
struct Balance {
    std::string keyset;                         // Keyset identifier
    cpp_int balance;                            // Net balance (issued - redeemed)
    
    // JSON serialization
    json to_json() const;
    static Balance from_json(const json& j);
};

/**
 * Issued tokens summary (from balance_issued view)
 */
struct BalanceIssued {
    std::string keyset;                         // Keyset identifier
    cpp_int balance;                            // Total issued amount
    
    // JSON serialization
    json to_json() const;
    static BalanceIssued from_json(const json& j);
};

/**
 * Redeemed tokens summary (from balance_redeemed view)
 */
struct BalanceRedeemed {
    std::string keyset;                         // Keyset identifier
    cpp_int balance;                            // Total redeemed amount
    
    // JSON serialization
    json to_json() const;
    static BalanceRedeemed from_json(const json& j);
};

//=============================================================================
// Utility Functions
//=============================================================================

/**
 * Convert Unit enum to string
 */
std::string unit_to_string(Unit unit);

/**
 * Convert string to Unit enum
 */
Unit string_to_unit(const std::string& unit_str);

/**
 * Convert Method enum to string
 */
std::string method_to_string(Method method);

/**
 * Convert string to Method enum
 */
Method string_to_method(const std::string& method_str);

/**
 * Convert ProofSpentState enum to string
 */
std::string proof_spent_state_to_string(ProofSpentState state);

/**
 * Convert string to ProofSpentState enum
 */
ProofSpentState string_to_proof_spent_state(const std::string& state_str);

/**
 * Convert MintQuoteState enum to string
 */
std::string mint_quote_state_to_string(MintQuoteState state);

/**
 * Convert string to MintQuoteState enum
 */
MintQuoteState string_to_mint_quote_state(const std::string& state_str);

/**
 * Convert MeltQuoteState enum to string
 */
std::string melt_quote_state_to_string(MeltQuoteState state);

/**
 * Convert string to MeltQuoteState enum
 */
MeltQuoteState string_to_melt_quote_state(const std::string& state_str);

/**
 * Convert timestamp to Unix timestamp (for database storage)
 */
int64_t timestamp_to_unix(const timestamp_t& tp);

/**
 * Convert Unix timestamp to timestamp (from database)
 */
timestamp_t unix_to_timestamp(int64_t unix_time);

/**
 * Get current timestamp
 */
timestamp_t now();

} // namespace cashu::core::models