#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/crypto/keys.py
// Key derivation functionality matching nutshell exactly
// Supports all historical versions (pre-0.12, 0.12-0.14, 0.15+)

#include "secp.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>
#include <boost/multiprecision/cpp_int.hpp>

namespace cashu::core::crypto {
    using namespace boost::multiprecision;

/**
 * @brief Deterministic derivation of keys for 2^n values using BIP32
 * 
 * Derives private keys for a given set of amounts using BIP32 derivation.
 * Each amount gets its own derived key at path: derivation_path/{index}'
 * 
 * @param mnemonic BIP39 mnemonic seed phrase
 * @param derivation_path BIP32 derivation path (e.g., "m/44'/1'/0'/0")
 * @param amounts List of amounts to derive keys for
 * @return Map from amount to derived private key
 */
std::unordered_map<cpp_int, PrivateKey> derive_keys(
    const std::string& mnemonic,
    const std::string& derivation_path,
    const std::vector<cpp_int>& amounts
);

/**
 * @brief Deprecated key derivation (pre-v0.15.0, v0.12-v0.14)
 * 
 * Legacy method using simple SHA256 hashing instead of BIP32.
 * Used for nutshell versions 0.12 through 0.14.
 * 
 * @param seed String seed for derivation
 * @param amounts List of amounts to derive keys for
 * @param derivation_path Derivation path suffix (concatenated with seed)
 * @return Map from amount to derived private key
 */
std::unordered_map<cpp_int, PrivateKey> derive_keys_deprecated_pre_0_15(
    const std::string& seed,
    const std::vector<cpp_int>& amounts,
    const std::string& derivation_path
);

/**
 * @brief Backwards compatible insecure key derivation (pre-v0.12) 
 * 
 * INSECURE legacy method with double-encoding bug. Used for nutshell
 * versions before 0.12. This method has a critical bug where it
 * double-encodes the hash (hexdigest -> encode -> take first 32 bytes)
 * which significantly reduces entropy. 
 * 
 * WARNING: This method is cryptographically insecure and should only
 * be used for backwards compatibility with old nutshell versions.
 * 
 * @param seed String seed for derivation
 * @param derivation_path Derivation path suffix
 * @return Map from amount to derived private key (fixed amounts: powers of 2)
 */
std::unordered_map<cpp_int, PrivateKey> derive_keys_backwards_compatible_insecure_pre_0_12(
    const std::string& seed,
    const std::string& derivation_path
);

/**
 * @brief Derive a single public key from seed
 * 
 * Creates a public key by hashing the seed with SHA256 and using
 * the result as a private key, then getting its public key.
 * 
 * @param seed String seed for derivation
 * @return Derived public key
 */
PublicKey derive_pubkey(const std::string& seed);

/**
 * @brief Derive public keys from private keys
 * 
 * Converts a map of private keys to corresponding public keys.
 * 
 * @param keys Map of private keys by amount
 * @param amounts List of amounts to derive public keys for
 * @return Map from amount to public key
 */
std::unordered_map<cpp_int, PublicKey> derive_pubkeys(
    const std::unordered_map<cpp_int, PrivateKey>& keys,
    const std::vector<cpp_int>& amounts
);

/**
 * @brief Deterministic derivation of keyset ID from public keys
 * 
 * Creates a unique identifier for a keyset by:
 * 1. Sorting public keys by amount
 * 2. Concatenating their serialized representations
 * 3. Hashing with SHA256
 * 4. Taking first 14 hex characters and prefixing with "00"
 * 
 * @param keys Map of public keys by amount
 * @return Keyset ID as hex string (format: "00" + 14 hex chars)
 */
std::string derive_keyset_id(const std::unordered_map<cpp_int, PublicKey>& keys);

/**
 * @brief Deprecated keyset ID derivation (pre-v0.15.0)
 * 
 * Legacy method that produces base64 keyset IDs instead of hex.
 * Kept for backwards compatibility.
 * 
 * @param keys Map of public keys by amount
 * @return Keyset ID as base64 string (12 characters)
 */
std::string derive_keyset_id_deprecated(const std::unordered_map<cpp_int, PublicKey>& keys);

/**
 * @brief Version-aware keyset ID derivation (nutshell compatible)
 * 
 * Automatically selects the correct keyset ID generation method based on 
 * the nutshell version for full backwards compatibility.
 * 
 * @param keys Map of public keys by amount
 * @param version Nutshell version string (e.g., "0.15.0")
 * @return Keyset ID in the format used by that version
 */
std::string derive_keyset_id_version_aware(
    const std::unordered_map<cpp_int, PublicKey>& keys,
    const std::string& version
);

/**
 * @brief Generate a random hash string
 * 
 * Returns a base64-urlsafe encoded random hash for use as identifiers.
 * Generates 30 random bytes and encodes them.
 * 
 * @return Random hash string (base64-urlsafe encoded)
 */
std::string random_hash();

// ---- BIP32 Helper Functions ----

/**
 * @brief BIP32 key derivation utility class
 * 
 * Wrapper around BIP32 functionality for deterministic key derivation.
 * Handles mnemonic seed parsing and path-based key derivation.
 */
class BIP32Helper {
public:
    /**
     * @brief Initialize from mnemonic seed (nutshell compatible)
     * @param mnemonic BIP39 mnemonic phrase (used directly as seed, not PBKDF2)
     * @param passphrase Optional passphrase (default: empty, ignored for nutshell compatibility)
     */
    explicit BIP32Helper(const std::string& mnemonic, const std::string& passphrase = "");
    
    /**
     * @brief Derive private key from BIP32 path
     * @param path BIP32 derivation path (e.g., "m/44'/1'/0'/0/0'")
     * @return Derived private key
     */
    PrivateKey get_privkey_from_path(const std::string& path);
    
    /**
     * @brief Check if a BIP32 path is valid
     * @param path Path to validate
     * @return True if path is valid
     */
    static bool is_valid_path(const std::string& path);

private:
    std::vector<uint8_t> seed_;
    std::vector<uint8_t> master_chain_code_;
    
    /**
     * @brief Parse BIP32 derivation path
     * @param path Path string to parse
     * @return Vector of derivation indices
     */
    std::vector<uint32_t> parse_path(const std::string& path);
    
    /**
     * @brief Derive key at specific index with chain code propagation
     * @param parent_key Parent private key
     * @param parent_chain_code Parent chain code
     * @param index Derivation index (with hardened bit if needed)
     * @return Pair of (derived private key, derived chain code)
     */
    std::pair<PrivateKey, std::vector<uint8_t>> derive_child_key_with_chain_code(
        const PrivateKey& parent_key, 
        const std::vector<uint8_t>& parent_chain_code,
        uint32_t index
    );
};

// ---- Version-aware Key Derivation ----

/**
 * @brief Version tuple for nutshell compatibility
 */
struct VersionTuple {
    int major;
    int minor; 
    int patch;
    
    VersionTuple(int maj, int min, int pat) : major(maj), minor(min), patch(pat) {}
    
    bool operator<(const VersionTuple& other) const {
        if (major != other.major) return major < other.major;
        if (minor != other.minor) return minor < other.minor;
        return patch < other.patch;
    }
    
    bool operator==(const VersionTuple& other) const {
        return major == other.major && minor == other.minor && patch == other.patch;
    }
};

/**
 * @brief Parse version string to tuple
 * @param version_str Version string like "0.15.0" 
 * @return Parsed version tuple
 */
VersionTuple parse_version(const std::string& version_str);

/**
 * @brief Version-aware key derivation (nutshell compatible)
 * 
 * Automatically selects the correct key derivation method based on the 
 * nutshell version. Supports all three historical methods for full
 * backwards compatibility.
 * 
 * @param seed_or_mnemonic Seed string or mnemonic (depends on version)
 * @param derivation_path BIP32 path or simple string (depends on version)
 * @param amounts List of amounts to derive keys for (or empty for pre-0.12)
 * @param version Nutshell version string (e.g., "0.15.0")
 * @return Map from amount to derived private key
 */
std::unordered_map<cpp_int, PrivateKey> derive_keys_version_aware(
    const std::string& seed_or_mnemonic,
    const std::string& derivation_path,
    const std::vector<cpp_int>& amounts,
    const std::string& version
);

// ---- Utility Functions ----

/**
 * @brief Generate standard Cashu amounts array
 * 
 * Creates the standard set of amounts used in Cashu: [1, 2, 4, 8, 16, ...]
 * up to a maximum amount.
 * 
 * @param max_amount Maximum amount to generate (must be power of 2)
 * @return Vector of powers of 2 up to max_amount
 */
std::vector<cpp_int> generate_standard_amounts(cpp_int max_amount = 1024);

/**
 * @brief Validate mnemonic phrase
 * 
 * Checks if a mnemonic phrase is valid according to BIP39 standard.
 * 
 * @param mnemonic Mnemonic phrase to validate
 * @return True if mnemonic is valid
 */
bool validate_mnemonic(const std::string& mnemonic);

/**
 * @brief Generate random mnemonic phrase
 * 
 * Creates a new BIP39 mnemonic phrase with specified entropy bits.
 * 
 * @param entropy_bits Bits of entropy (128, 160, 192, 224, or 256)
 * @return Generated mnemonic phrase
 */
std::string generate_mnemonic(int entropy_bits = 256);

} // namespace cashu::core::crypto