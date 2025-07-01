#include "cashu/core/crypto/keys.hpp"
#include "cashu/core/crypto/secp.hpp"
#include "cashu/core/crypto/bip39.hpp"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <regex>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::crypto {

//=============================================================================
// Utility Functions
//=============================================================================

namespace {
    vector<uint8_t> sha256(const vector<uint8_t>& data) {
        vector<uint8_t> hash(32);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }
    
    vector<uint8_t> sha256(const string& data) {
        vector<uint8_t> hash(32);
        SHA256(reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), hash.data());
        return hash;
    }
    
    vector<uint8_t> hmac_sha512(const vector<uint8_t>& key, const vector<uint8_t>& data) {
        vector<uint8_t> result(64);
        unsigned int len = 64;
        
        HMAC(EVP_sha512(), key.data(), key.size(), data.data(), data.size(), result.data(), &len);
        return result;
    }
    
    string bytes_to_hex(const vector<uint8_t>& bytes) {
        ostringstream oss;
        for (uint8_t byte : bytes) {
            oss << setfill('0') << setw(2) << hex << static_cast<int>(byte);
        }
        return oss.str();
    }
    
    string bytes_to_base64(const vector<uint8_t>& bytes) {
        string encoded;
        const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        for (size_t i = 0; i < bytes.size(); i += 3) {
            uint32_t val = (bytes[i] << 16);
            if (i + 1 < bytes.size()) val |= (bytes[i + 1] << 8);
            if (i + 2 < bytes.size()) val |= bytes[i + 2];
            
            encoded += chars[(val >> 18) & 0x3F];
            encoded += chars[(val >> 12) & 0x3F];
            encoded += (i + 1 < bytes.size()) ? chars[(val >> 6) & 0x3F] : '=';
            encoded += (i + 2 < bytes.size()) ? chars[val & 0x3F] : '=';
        }
        
        return encoded;
    }
    
    string bytes_to_base64_urlsafe(const vector<uint8_t>& bytes) {
        string base64 = bytes_to_base64(bytes);
        // Replace + with - and / with _
        for (char& c : base64) {
            if (c == '+') c = '-';
            else if (c == '/') c = '_';
        }
        // Remove padding
        base64.erase(find(base64.begin(), base64.end(), '='), base64.end());
        return base64;
    }
    
    // vector<uint8_t> string_to_bytes(const string& str) {
    //     return vector<uint8_t>(str.begin(), str.end());
    // }
    
    // uint32_t big_endian_to_uint32(const vector<uint8_t>& bytes, size_t offset = 0) {
    //     return (static_cast<uint32_t>(bytes[offset]) << 24) |
    //            (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
    //            (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
    //            static_cast<uint32_t>(bytes[offset + 3]);
    // }
    
    vector<uint8_t> uint32_to_big_endian(uint32_t value) {
        return {
            static_cast<uint8_t>((value >> 24) & 0xFF),
            static_cast<uint8_t>((value >> 16) & 0xFF),
            static_cast<uint8_t>((value >> 8) & 0xFF),
            static_cast<uint8_t>(value & 0xFF)
        };
    }
    
    // NOTE: PBKDF2 implementation removed for nutshell compatibility
    // Nutshell uses direct mnemonic encoding, not PBKDF2
    
    // NOTE: mnemonic_to_seed function removed for nutshell compatibility
    // Nutshell uses direct mnemonic.encode() as seed, not BIP39 PBKDF2
}

//=============================================================================
// BIP32 Implementation
//=============================================================================

BIP32Helper::BIP32Helper(const string& mnemonic, const string& passphrase) {
    // NUTSHELL COMPATIBILITY: Use mnemonic directly as seed (not BIP39 PBKDF2)
    // This matches nutshell's BIP32.from_seed(mnemonic.encode()) behavior
    seed_.assign(mnemonic.begin(), mnemonic.end());
    
    // Note: passphrase is ignored for nutshell compatibility
    // In nutshell, they don't use PBKDF2, just the raw mnemonic bytes
    (void)passphrase; // Suppress unused parameter warning
    
    // Derive master private key and chain code from seed using HMAC-SHA512
    string seed_str = "Bitcoin seed";
    vector<uint8_t> seed_bytes(seed_str.begin(), seed_str.end());
    vector<uint8_t> master_result = hmac_sha512(seed_bytes, seed_);
    
    // Store master chain code (last 32 bytes of HMAC result)
    master_chain_code_.assign(master_result.begin() + 32, master_result.end());
}

vector<uint32_t> BIP32Helper::parse_path(const string& path) {
    vector<uint32_t> indices;
    
    if (path.empty() || path[0] != 'm') {
        throw invalid_argument("Path must start with 'm'");
    }
    
    // Split path by '/'
    stringstream ss(path.substr(1)); // Skip 'm'
    string segment;
    
    while (getline(ss, segment, '/')) {
        if (segment.empty()) continue;
        
        bool hardened = false;
        if (segment.back() == '\'') {
            hardened = true;
            segment.pop_back();
        }
        
        uint32_t index = static_cast<uint32_t>(stoul(segment));
        if (hardened) {
            index |= 0x80000000; // Set hardened bit
        }
        
        indices.push_back(index);
    }
    
    return indices;
}

pair<PrivateKey, vector<uint8_t>> BIP32Helper::derive_child_key_with_chain_code(
    const PrivateKey& parent_key, 
    const vector<uint8_t>& parent_chain_code, 
    uint32_t index
) {
    // BIP32 standard derivation
    vector<uint8_t> parent_bytes = parent_key.serialize();
    vector<uint8_t> index_bytes = uint32_to_big_endian(index);
    
    vector<uint8_t> hmac_input;
    
    bool hardened = (index & 0x80000000) != 0;
    
    if (hardened) {
        // Hardened derivation: HMAC(chain_code, 0x00 || parent_private_key || index)
        hmac_input.push_back(0x00);
        hmac_input.insert(hmac_input.end(), parent_bytes.begin(), parent_bytes.end());
    } else {
        // Non-hardened derivation: HMAC(chain_code, parent_public_key || index)
        PublicKey parent_pubkey = parent_key.pubkey();
        vector<uint8_t> pubkey_bytes = parent_pubkey.serialize(true); // Compressed
        hmac_input.insert(hmac_input.end(), pubkey_bytes.begin(), pubkey_bytes.end());
    }
    
    hmac_input.insert(hmac_input.end(), index_bytes.begin(), index_bytes.end());
    
    // Use the parent chain code (not the master chain code!)
    // HMAC-SHA512(parent_chain_code, input)
    vector<uint8_t> hmac_result = hmac_sha512(parent_chain_code, hmac_input);
    
    // Left 32 bytes = child private key scalar
    vector<uint8_t> child_key_scalar(hmac_result.begin(), hmac_result.begin() + 32);
    // Right 32 bytes = child chain code
    vector<uint8_t> child_chain_code(hmac_result.begin() + 32, hmac_result.end());
    
    // Convert to cpp_int and add to parent key (mod curve order)
    cpp_int scalar = 0;
    for (size_t i = 0; i < 32; ++i) {
        scalar = (scalar << 8) + child_key_scalar[i];
    }
    
    // child_key = (parent_key + scalar) mod curve_order
    cpp_int parent_scalar = parent_key.raw_value();
    cpp_int child_scalar = (parent_scalar + scalar) % secp256k1_const::CURVE_ORDER;
    
    return make_pair(PrivateKey(child_scalar), child_chain_code);
}

PrivateKey BIP32Helper::get_privkey_from_path(const string& path) {
    vector<uint32_t> indices = parse_path(path);
    
    // Derive master private key from seed using HMAC-SHA512
    string seed_str = "Bitcoin seed";
    vector<uint8_t> seed_bytes(seed_str.begin(), seed_str.end());
    vector<uint8_t> master_result = hmac_sha512(seed_bytes, seed_);
    
    // Master private key is first 32 bytes
    vector<uint8_t> master_key_bytes(master_result.begin(), master_result.begin() + 32);
    // Master chain code is last 32 bytes
    vector<uint8_t> current_chain_code(master_result.begin() + 32, master_result.end());
    
    PrivateKey current_key(master_key_bytes);
    
    // Derive each level, propagating the chain code
    for (uint32_t index : indices) {
        auto result = derive_child_key_with_chain_code(current_key, current_chain_code, index);
        current_key = result.first;
        current_chain_code = result.second;
    }
    
    return current_key;
}

bool BIP32Helper::is_valid_path(const string& path) {
    if (path.empty() || path[0] != 'm') {
        return false;
    }
    
    // Basic validation - should start with m and contain only digits, /, and '
    regex path_regex(R"(^m(/\d+'?)*$)");
    return regex_match(path, path_regex);
}

//=============================================================================
// Key Derivation Functions
//=============================================================================

unordered_map<cpp_int, PrivateKey> derive_keys(
    const string& mnemonic,
    const string& derivation_path,
    const vector<cpp_int>& amounts
) {
    BIP32Helper bip32(mnemonic);
    unordered_map<cpp_int, PrivateKey> result;
    
    for (size_t i = 0; i < amounts.size(); ++i) {
        string full_path = derivation_path + "/" + to_string(i) + "'";
        PrivateKey key = bip32.get_privkey_from_path(full_path);
        result[amounts[i]] = key;
    }
    
    return result;
}

unordered_map<cpp_int, PrivateKey> derive_keys_deprecated_pre_0_15(
    const string& seed,
    const vector<cpp_int>& amounts,
    const string& derivation_path
) {
    unordered_map<cpp_int, PrivateKey> result;
    
    // NUTSHELL COMPATIBILITY: Hash combination is seed + derivation_path + str(i)
    // This matches: hashlib.sha256((seed + derivation_path + str(i)).encode("utf-8")).digest()[:32]
    for (size_t i = 0; i < amounts.size(); ++i) {
        string combined = seed + derivation_path + to_string(i);
        vector<uint8_t> hash = sha256(combined);
        
        // Take first 32 bytes as private key
        vector<uint8_t> key_bytes(hash.begin(), hash.begin() + 32);
        result[amounts[i]] = PrivateKey(key_bytes);
    }
    
    return result;
}

unordered_map<cpp_int, PrivateKey> derive_keys_backwards_compatible_insecure_pre_0_12(
    const string& seed,
    const string& derivation_path
) {
    unordered_map<cpp_int, PrivateKey> result;
    
    // NUTSHELL COMPATIBILITY: Replicate the double-encoding bug exactly
    // This matches: hashlib.sha256((seed + derivation_path + str(i)).encode("utf-8")).hexdigest().encode("utf-8")[:32]
    // 
    // The bug: instead of using .digest()[:32], nutshell used .hexdigest().encode("utf-8")[:32]
    // This means: SHA256 -> hex string -> UTF-8 bytes -> take first 32 bytes
    // This reduces entropy significantly because hex chars are limited to [0-9a-f]
    
    // Fixed amounts for pre-0.12: powers of 2 up to max_order (default 64)
    // nutshell: amounts = [2**i for i in range(settings.max_order)]
    // Assuming max_order = 6 (like default): [1, 2, 4, 8, 16, 32]
    vector<cpp_int> fixed_amounts = {1, 2, 4, 8, 16, 32};
    
    for (size_t i = 0; i < fixed_amounts.size(); ++i) {
        string combined = seed + derivation_path + to_string(i);
        
        // Step 1: SHA256 hash to get bytes
        vector<uint8_t> hash_bytes = sha256(combined);
        
        // Step 2: Convert to hex string (this is .hexdigest())
        string hex_digest = bytes_to_hex(hash_bytes);
        
        // Step 3: Encode hex string to UTF-8 bytes (this is .encode("utf-8"))
        vector<uint8_t> encoded_hex(hex_digest.begin(), hex_digest.end());
        
        // Step 4: Take first 32 bytes (this is [:32])
        vector<uint8_t> key_bytes(encoded_hex.begin(), 
                                  encoded_hex.begin() + min(static_cast<size_t>(32), encoded_hex.size()));
        
        // Pad with zeros if less than 32 bytes (should not happen with SHA256 hex)
        if (key_bytes.size() < 32) {
            key_bytes.resize(32, 0);
        }
        
        result[fixed_amounts[i]] = PrivateKey(key_bytes);
    }
    
    return result;
}

PublicKey derive_pubkey(const string& seed) {
    vector<uint8_t> hash = sha256(seed);
    vector<uint8_t> key_bytes(hash.begin(), hash.begin() + 32);
    PrivateKey private_key(key_bytes);
    return private_key.pubkey();
}

unordered_map<cpp_int, PublicKey> derive_pubkeys(
    const unordered_map<cpp_int, PrivateKey>& keys,
    const vector<cpp_int>& amounts
) {
    unordered_map<cpp_int, PublicKey> result;
    
    for (cpp_int amount : amounts) {
        auto it = keys.find(amount);
        if (it != keys.end()) {
            result[amount] = it->second.pubkey();
        }
    }
    
    return result;
}

string derive_keyset_id(const unordered_map<cpp_int, PublicKey>& keys) {
    // Sort keys by amount
    vector<pair<cpp_int, PublicKey>> sorted_keys(keys.begin(), keys.end());
    sort(sorted_keys.begin(), sorted_keys.end());
    
    // Concatenate serialized public keys
    vector<uint8_t> pubkeys_concat;
    for (const auto& [amount, pubkey] : sorted_keys) {
        vector<uint8_t> serialized = pubkey.serialize(true); // Compressed
        pubkeys_concat.insert(pubkeys_concat.end(), serialized.begin(), serialized.end());
    }
    
    // Hash concatenated pubkeys
    vector<uint8_t> hash = sha256(pubkeys_concat);
    
    // Take first 14 hex characters and prefix with "00"
    string hex_hash = bytes_to_hex(hash);
    return "00" + hex_hash.substr(0, 14);
}

string derive_keyset_id_deprecated(const unordered_map<cpp_int, PublicKey>& keys) {
    // Sort keys by amount
    vector<pair<cpp_int, PublicKey>> sorted_keys(keys.begin(), keys.end());
    sort(sorted_keys.begin(), sorted_keys.end());
    
    // Concatenate hex-encoded public keys
    string pubkeys_concat;
    for (const auto& [amount, pubkey] : sorted_keys) {
        vector<uint8_t> serialized = pubkey.serialize(true); // Compressed
        pubkeys_concat += bytes_to_hex(serialized);
    }
    
    // Hash the concatenated string
    vector<uint8_t> hash = sha256(pubkeys_concat);
    
    // Encode as base64 and take first 12 characters
    string base64_hash = bytes_to_base64(hash);
    return base64_hash.substr(0, 12);
}

string random_hash() {
    vector<uint8_t> random_bytes(30);
    
    if (RAND_bytes(random_bytes.data(), 30) != 1) {
        throw runtime_error("Failed to generate random bytes");
    }
    
    return bytes_to_base64_urlsafe(random_bytes);
}

//=============================================================================
// Version-aware Key Derivation
//=============================================================================

VersionTuple parse_version(const string& version_str) {
    // Parse version string like "0.15.0" or "v0.15.0"
    string clean_version = version_str;
    if (!clean_version.empty() && clean_version[0] == 'v') {
        clean_version = clean_version.substr(1);
    }
    
    stringstream ss(clean_version);
    string segment;
    vector<int> parts;
    
    while (getline(ss, segment, '.')) {
        if (!segment.empty()) {
            parts.push_back(stoi(segment));
        }
    }
    
    // Default to 0 if missing parts
    int major = parts.size() > 0 ? parts[0] : 0;
    int minor = parts.size() > 1 ? parts[1] : 0;
    int patch = parts.size() > 2 ? parts[2] : 0;
    
    return VersionTuple(major, minor, patch);
}

unordered_map<cpp_int, PrivateKey> derive_keys_version_aware(
    const string& seed_or_mnemonic,
    const string& derivation_path,
    const vector<cpp_int>& amounts,
    const string& version
) {
    VersionTuple version_tuple = parse_version(version);
    
    // Version comparison logic matching nutshell MintKeyset.generate_keys()
    if (version_tuple < VersionTuple(0, 12, 0)) {
        // Pre-0.12: Use insecure method with fixed amounts
        return derive_keys_backwards_compatible_insecure_pre_0_12(seed_or_mnemonic, derivation_path);
    }
    else if (version_tuple < VersionTuple(0, 15, 0)) {
        // 0.12 - 0.14: Use non-BIP32 method
        return derive_keys_deprecated_pre_0_15(seed_or_mnemonic, amounts, derivation_path);
    }
    else {
        // 0.15.0+: Use current BIP32 method
        return derive_keys(seed_or_mnemonic, derivation_path, amounts);
    }
}

string derive_keyset_id_version_aware(
    const unordered_map<cpp_int, PublicKey>& keys,
    const string& version
) {
    VersionTuple version_tuple = parse_version(version);
    
    // Version comparison logic matching nutshell keyset ID generation
    if (version_tuple < VersionTuple(0, 15, 0)) {
        // Pre-0.15: Use deprecated base64 method
        return derive_keyset_id_deprecated(keys);
    }
    else {
        // 0.15.0+: Use current hex method
        return derive_keyset_id(keys);
    }
}

//=============================================================================
// Utility Functions
//=============================================================================

vector<cpp_int> generate_standard_amounts(cpp_int max_amount) {
    vector<cpp_int> amounts;
    for (cpp_int amount = 1; amount <= max_amount; amount *= 2) {
        amounts.push_back(amount);
    }
    return amounts;
}

bool validate_mnemonic(const string& mnemonic) {
    // Use the complete BIP39 validation from new BIP39 class
    return BIP39::validate_mnemonic(mnemonic);
}

string generate_mnemonic(int entropy_bits) {
    // Use the complete BIP39 implementation from new BIP39 class
    return BIP39::generate_mnemonic(entropy_bits);
}

} // namespace cashu::core::crypto