#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/base.py
// Core base classes and data structures for Cashu protocol
// 100% compatible with nutshell Proof, DLEQ, Amount, Unit, BlindedMessage, BlindedSignature classes

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <variant>
#include <unordered_map>
#include <boost/multiprecision/cpp_int.hpp>

#include "cashu/core/settings.hpp"
#include "cashu/core/crypto/secp.hpp"

namespace cashu::core::base {
    using namespace boost::multiprecision;

// Forward declarations
class Proof;
class BlindedMessage;
class BlindedSignature;
class MintQuote;
class MeltQuote;

/**
 * Discrete Log Equality (DLEQ) Proof
 * NUTSHELL COMPATIBILITY: Matches DLEQ class in nutshell base.py exactly
 */
class DLEQ {
public:
    DLEQ() = default;
    DLEQ(const std::string& e, const std::string& s);
    
    std::string e;  // challenge
    std::string s;  // signature
    
    // Serialization
    std::string to_json() const;
    static DLEQ from_json(const std::string& json);
};

/**
 * DLEQ Proof for wallet (includes blinding factor)
 * NUTSHELL COMPATIBILITY: Matches DLEQWallet class in nutshell base.py exactly
 */
class DLEQWallet {
public:
    DLEQWallet() = default;
    DLEQWallet(const std::string& e, const std::string& s, const std::string& r);
    
    std::string e;  // challenge
    std::string s;  // signature  
    std::string r;  // blinding factor (unknown to mint)
    
    // Serialization
    std::string to_json() const;
    static DLEQWallet from_json(const std::string& json);
};

/**
 * Proof spent state enumeration
 * NUTSHELL COMPATIBILITY: Matches ProofSpentState enum in nutshell base.py exactly
 */
enum class ProofSpentState {
    UNSPENT,
    SPENT, 
    PENDING
};

std::string to_string(ProofSpentState state);
ProofSpentState proof_spent_state_from_string(const std::string& str);

/**
 * Proof state information
 * NUTSHELL COMPATIBILITY: Matches ProofState class in nutshell base.py exactly
 */
class ProofState {
public:
    ProofState() = default;
    ProofState(const std::string& Y, ProofSpentState state, const std::optional<std::string>& witness = std::nullopt);
    
    std::string Y;  // hash of secret
    ProofSpentState state;
    std::optional<std::string> witness;
    
    // State checking properties (matches nutshell)
    bool unspent() const { return state == ProofSpentState::UNSPENT; }
    bool spent() const { return state == ProofSpentState::SPENT; }
    bool pending() const { return state == ProofSpentState::PENDING; }
    
    // Identifier for event management
    std::string identifier() const { return Y; }
    
    // Serialization
    std::string to_json() const;
    static ProofState from_json(const std::string& json);
};

/**
 * HTLC (Hash Time Lock Contract) Witness
 * NUTSHELL COMPATIBILITY: Matches HTLCWitness class in nutshell base.py exactly
 */
class HTLCWitness {
public:
    HTLCWitness() = default;
    
    std::optional<std::string> preimage;
    std::optional<std::vector<std::string>> signatures;
    
    // Factory method
    static HTLCWitness from_witness(const std::string& witness);
    
    // Serialization
    std::string to_json() const;
};

/**
 * P2PK (Pay-to-Public-Key) Witness
 * NUTSHELL COMPATIBILITY: Matches P2PKWitness class in nutshell base.py exactly
 */
class P2PKWitness {
public:
    P2PKWitness() = default;
    P2PKWitness(const std::vector<std::string>& signatures);
    
    std::vector<std::string> signatures;
    
    // Factory method
    static P2PKWitness from_witness(const std::string& witness);
    
    // Serialization
    std::string to_json() const;
};

/**
 * Value token (Proof)
 * NUTSHELL COMPATIBILITY: Matches Proof class in nutshell base.py exactly
 * Core data structure for entire Cashu system
 */
class Proof {
public:
    Proof() = default;
    Proof(const std::string& id, const cpp_int& amount, const std::string& secret, const std::string& C);
    
    // Core fields (match nutshell Proof exactly)
    std::string id = "";           // keyset id
    cpp_int amount = 0;            // token amount
    std::string secret = "";       // secret message to be blinded
    std::string Y = "";            // hash_to_curve(secret) - computed automatically
    std::string C = "";            // signature on secret, unblinded by wallet
    std::optional<DLEQWallet> dleq;  // DLEQ proof
    std::optional<std::string> witness;  // witness for spending condition
    
    // Wallet management fields (match nutshell)
    bool reserved = false;
    std::string send_id = "";
    std::string time_created = "";
    std::string time_reserved = "";
    std::string derivation_path = "";
    std::optional<std::string> mint_id;   // mint operation id
    std::optional<std::string> melt_id;   // melt operation id
    
    // Factory method (matches nutshell)
    static Proof from_dict(const std::unordered_map<std::string, std::variant<std::string, cpp_int, bool>>& proof_dict);
    
    // Serialization methods (match nutshell exactly)
    std::unordered_map<std::string, std::variant<std::string, cpp_int, bool>> to_dict(bool include_dleq = false) const;
    std::string to_base64() const;
    std::unordered_map<std::string, std::variant<std::string, cpp_int, bool>> to_dict_no_dleq() const;
    std::unordered_map<std::string, std::variant<std::string, cpp_int, bool>> to_dict_no_secret() const;
    
    // Witness parsing properties (match nutshell)
    std::vector<std::string> p2pksigs() const;
    std::optional<std::string> htlcpreimage() const;
    std::optional<std::vector<std::string>> htlcsigs() const;
    
private:
    void compute_Y();  // Compute Y = hash_to_curve(secret) using nutshell method
};

/**
 * Unit enumeration for different currencies
 * NUTSHELL COMPATIBILITY: Matches Unit enum in nutshell base.py exactly
 */
enum class Unit {
    SAT = 0,    // satoshis
    MSAT = 1,   // millisatoshis  
    USD = 2,    // US dollars (cents)
    EUR = 3,    // Euros (cents)
    BTC = 4,    // Bitcoin
    AUTH = 999  // Authentication tokens
};

std::string to_string(Unit unit);
Unit unit_from_string(const std::string& str);

/**
 * Amount class with unit conversion
 * NUTSHELL COMPATIBILITY: Matches Amount class in nutshell base.py exactly
 */
class Amount {
public:
    Amount(Unit unit, const cpp_int& amount);
    
    Unit unit;
    cpp_int amount;
    
    // Unit conversion (matches nutshell exactly)
    Amount to(Unit to_unit, const std::optional<std::string>& round = std::nullopt) const;
    
    // String formatting (matches nutshell)
    std::string to_float_string() const;
    std::string str() const;
    
    // Factory methods (matches nutshell)
    static Amount from_float(double amount, Unit unit);
    
    // Arithmetic operators (matches nutshell)
    Amount operator+(const Amount& other) const;
    Amount operator+(int other) const;
    Amount operator-(const Amount& other) const;
    Amount operator-(int other) const;
    Amount operator*(int other) const;
    
    // Comparison operators (matches nutshell)
    bool operator==(const Amount& other) const;
    bool operator==(int other) const;
    bool operator<(const Amount& other) const;
    bool operator<(int other) const;
    bool operator<=(const Amount& other) const;
    bool operator<=(int other) const;
    bool operator>(const Amount& other) const;
    bool operator>(int other) const;
    bool operator>=(const Amount& other) const;
    bool operator>=(int other) const;
    
private:
    std::string sat_to_btc() const;
    std::string msat_to_btc() const;
    std::string cents_to_usd() const;
};

/**
 * Lightning payment method enumeration
 * NUTSHELL COMPATIBILITY: Matches Method enum in nutshell base.py exactly
 */
enum class Method {
    BOLT11 = 0
};

std::string to_string(Method method);
Method method_from_string(const std::string& str);

/**
 * Melt quote state enumeration
 * NUTSHELL COMPATIBILITY: Matches MeltQuoteState enum in nutshell base.py exactly
 */
enum class MeltQuoteState {
    UNPAID,
    PENDING,
    PAID
};

std::string to_string(MeltQuoteState state);
MeltQuoteState melt_quote_state_from_string(const std::string& str);

/**
 * Mint quote state enumeration  
 * NUTSHELL COMPATIBILITY: Matches MintQuoteState enum in nutshell base.py exactly
 */
enum class MintQuoteState {
    UNPAID,
    PAID,
    PENDING,
    ISSUED
};

std::string to_string(MintQuoteState state);
MintQuoteState mint_quote_state_from_string(const std::string& str);

/**
 * Blinded message for mint signing
 * NUTSHELL COMPATIBILITY: Matches BlindedMessage class in nutshell base.py exactly
 */
class BlindedMessage {
public:
    BlindedMessage() = default;
    BlindedMessage(const cpp_int& amount, const std::string& id, const std::string& B_);
    
    cpp_int amount;        // token amount
    std::string id;        // keyset id
    std::string B_;        // hex-encoded blinded message
    
    // Serialization (matches nutshell)
    std::string to_json() const;
    static BlindedMessage from_json(const std::string& json);
};

/**
 * Blinded signature from mint
 * NUTSHELL COMPATIBILITY: Matches BlindedSignature class in nutshell base.py exactly
 */
class BlindedSignature {
public:
    BlindedSignature() = default;
    BlindedSignature(const std::string& id, const cpp_int& amount, const std::string& C_, const std::optional<DLEQ>& dleq = std::nullopt);
    
    std::string id;     // keyset id
    cpp_int amount;     // token amount
    std::string C_;     // hex-encoded signature
    std::optional<DLEQ> dleq;  // DLEQ proof
    
    // Serialization (matches nutshell)
    std::string to_json() const;
    static BlindedSignature from_json(const std::string& json);
};

/**
 * Melt quote for Lightning payments
 * NUTSHELL COMPATIBILITY: Matches MeltQuote class in nutshell base.py exactly
 */
class MeltQuote {
public:
    MeltQuote() = default;
    
    std::string quote;
    std::string method;
    std::string request;
    std::string checking_id;
    std::string unit;
    cpp_int amount;
    int fee_reserve;
    MeltQuoteState state;
    std::optional<int> created_time;
    std::optional<int> paid_time;
    int fee_paid = 0;
    std::optional<std::string> payment_preimage;
    std::optional<int> expiry;
    std::optional<std::vector<BlindedMessage>> outputs;
    std::optional<std::vector<BlindedSignature>> change;
    std::optional<std::string> mint;
    
    // State checking methods (match nutshell)
    bool unpaid() const { return state == MeltQuoteState::UNPAID; }
    bool pending() const { return state == MeltQuoteState::PENDING; }
    bool paid() const { return state == MeltQuoteState::PAID; }
    
    // Serialization
    std::string to_json() const;
    static MeltQuote from_json(const std::string& json);
};

/**
 * Mint quote for token creation
 * NUTSHELL COMPATIBILITY: Matches MintQuote class in nutshell base.py exactly
 */
class MintQuote {
public:
    MintQuote() = default;
    
    std::string quote;
    std::string method;
    std::string request;
    std::string checking_id;
    std::string unit;
    cpp_int amount;
    MintQuoteState state;
    std::optional<int> created_time;
    std::optional<int> paid_time;
    std::optional<int> expiry;
    std::optional<std::string> mint;
    std::optional<std::string> privkey;
    std::optional<std::string> pubkey;
    
    // State checking methods (match nutshell)
    bool unpaid() const { return state == MintQuoteState::UNPAID; }
    bool paid() const { return state == MintQuoteState::PAID; }
    bool pending() const { return state == MintQuoteState::PENDING; }
    bool issued() const { return state == MintQuoteState::ISSUED; }
    
    // Serialization
    std::string to_json() const;
    static MintQuote from_json(const std::string& json);
};

} // namespace cashu::core::base