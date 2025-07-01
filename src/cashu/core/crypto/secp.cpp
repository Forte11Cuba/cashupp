// NUTSHELL COMPATIBILITY: cashu/core/crypto/secp.py
// Complete secp256k1 implementation providing C++ interface compatible with nutshell

#include "cashu/core/crypto/secp.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <random>
#include <cassert>
#include <cstring>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::crypto {

// Global secp256k1 context (thread-safe)
static secp256k1_context* get_secp_context() {
    static secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    return ctx;
}

//=============================================================================
// Curve Constants
//=============================================================================

namespace secp256k1_const {
    const cpp_int CURVE_ORDER("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    
    const vector<uint8_t> GENERATOR_POINT = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 
        0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
    };
    
    const cpp_int FIELD_PRIME("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
}

//=============================================================================
// Utility Functions
//=============================================================================

namespace secp_utils {
    
    vector<uint8_t> hex_to_bytes(const string& hex) {
        string clean_hex = hex;
        if (clean_hex.substr(0, 2) == "0x" || clean_hex.substr(0, 2) == "0X") {
            clean_hex = clean_hex.substr(2);
        }
        
        if (clean_hex.length() % 2 != 0) {
            clean_hex = "0" + clean_hex;
        }
        
        vector<uint8_t> result;
        result.reserve(clean_hex.length() / 2);
        
        for (size_t i = 0; i < clean_hex.length(); i += 2) {
            unsigned int byte;
            istringstream hex_stream(clean_hex.substr(i, 2));
            hex_stream >> std::hex >> byte;
            result.push_back(static_cast<uint8_t>(byte));
        }
        
        return result;
    }
    
    string bytes_to_hex(const vector<uint8_t>& bytes) {
        ostringstream oss;
        for (uint8_t byte : bytes) {
            oss << setfill('0') << setw(2) << std::hex << static_cast<int>(byte);
        }
        return oss.str();
    }
    
    bool is_valid_private_key(const cpp_int& value) {
        return value > 0 && value < secp256k1_const::CURVE_ORDER;
    }
    
    PrivateKey generate_random_key() {
        vector<uint8_t> random_bytes(32);
        
        // Use OpenSSL for cryptographically secure random bytes
        if (RAND_bytes(random_bytes.data(), 32) != 1) {
            // Fallback to C++ random if OpenSSL fails
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<uint8_t> dis(0, 255);
            
            for (auto& byte : random_bytes) {
                byte = dis(gen);
            }
        }
        
        return PrivateKey(random_bytes);
    }
}

//=============================================================================
// PrivateKey Implementation
//=============================================================================

PrivateKey::PrivateKey() {
    // Generate random private key
    *this = secp_utils::generate_random_key();
}

PrivateKey::PrivateKey(const vector<uint8_t>& key_data) {
    if (key_data.size() != 32) {
        throw invalid_argument("Private key must be exactly 32 bytes");
    }
    
    // Convert bytes to cpp_int (big endian)
    private_key_ = 0;
    for (size_t i = 0; i < 32; ++i) {
        private_key_ = (private_key_ << 8) + key_data[i];
    }
    
    validate_key();
}

PrivateKey::PrivateKey(const cpp_int& key_value) : private_key_(key_value) {
    validate_key();
}

PrivateKey::PrivateKey(const string& hex_string) {
    vector<uint8_t> key_data = secp_utils::hex_to_bytes(hex_string);
    if (key_data.size() != 32) {
        throw invalid_argument("Private key hex must represent exactly 32 bytes");
    }
    
    // Convert to cpp_int
    private_key_ = 0;
    for (size_t i = 0; i < 32; ++i) {
        private_key_ = (private_key_ << 8) + key_data[i];
    }
    
    validate_key();
}

void PrivateKey::validate_key() const {
    if (!secp_utils::is_valid_private_key(private_key_)) {
        throw invalid_argument("Private key must be in range [1, curve_order)");
    }
}

PublicKey PrivateKey::pubkey() const {
    // Convert cpp_int to 32-byte array
    vector<uint8_t> privkey_bytes(32, 0);
    
    cpp_int temp = private_key_;
    for (int i = 31; i >= 0; --i) {
        privkey_bytes[i] = static_cast<uint8_t>(temp & 0xFF);
        temp >>= 8;
    }
    
    // Generate public key using secp256k1
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(get_secp_context(), &pubkey, privkey_bytes.data())) {
        throw runtime_error("Failed to create public key from private key");
    }
    
    // Serialize to compressed format
    vector<uint8_t> pubkey_compressed(33);
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(
        get_secp_context(), 
        pubkey_compressed.data(), 
        &output_len, 
        &pubkey, 
        SECP256K1_EC_COMPRESSED
    );
    
    return PublicKey(pubkey_compressed, false);
}

PrivateKey PrivateKey::tweak_add(const cpp_int& scalar) const {
    cpp_int result = (private_key_ + scalar) % secp256k1_const::CURVE_ORDER;
    return PrivateKey(result);
}

PrivateKey PrivateKey::tweak_mul(const cpp_int& scalar) const {
    cpp_int result = (private_key_ * scalar) % secp256k1_const::CURVE_ORDER;
    return PrivateKey(result);
}

cpp_int PrivateKey::raw_value() const {
    return private_key_;
}

vector<uint8_t> PrivateKey::serialize() const {
    vector<uint8_t> result(32, 0);
    
    cpp_int temp = private_key_;
    for (int i = 31; i >= 0; --i) {
        result[i] = static_cast<uint8_t>(temp & 0xFF);
        temp >>= 8;
    }
    
    return result;
}

string PrivateKey::to_hex() const {
    return secp_utils::bytes_to_hex(serialize());
}

vector<uint8_t> PrivateKey::sign(const vector<uint8_t>& message) const {
    // Hash the message with SHA256
    vector<uint8_t> hash(32);
    SHA256(message.data(), message.size(), hash.data());
    
    // Convert private key to bytes
    vector<uint8_t> privkey_bytes = serialize();
    
    // Create signature
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(get_secp_context(), &signature, hash.data(), privkey_bytes.data(), nullptr, nullptr)) {
        throw runtime_error("Failed to create signature");
    }
    
    // Serialize signature to DER format
    vector<uint8_t> der_signature(72);  // Maximum DER signature size
    size_t signature_len = 72;
    secp256k1_ecdsa_signature_serialize_der(get_secp_context(), der_signature.data(), &signature_len, &signature);
    
    der_signature.resize(signature_len);
    return der_signature;
}

bool PrivateKey::operator==(const PrivateKey& other) const {
    return private_key_ == other.private_key_;
}

//=============================================================================
// PublicKey Implementation  
//=============================================================================

PublicKey::PublicKey() : is_compressed_(true) {
    // Initialize with generator point
    point_data_ = secp256k1_const::GENERATOR_POINT;
}

PublicKey::PublicKey(const vector<uint8_t>& point_data, bool raw) {
    init_from_data(point_data, raw);
}

PublicKey::PublicKey(const string& hex_string) {
    vector<uint8_t> data = secp_utils::hex_to_bytes(hex_string);
    init_from_data(data, false);
}

void PublicKey::init_from_data(const vector<uint8_t>& data, bool raw) {
    if (raw) {
        // Raw format: 64 bytes of uncompressed point data (x, y coordinates)
        if (data.size() != 64) {
            throw invalid_argument("Raw public key data must be exactly 64 bytes");
        }
        
        // Convert to uncompressed format (0x04 + x + y)
        point_data_.resize(65);
        point_data_[0] = 0x04;
        copy(data.begin(), data.end(), point_data_.begin() + 1);
        is_compressed_ = false;
    } else {
        // Standard format: compressed (33 bytes) or uncompressed (65 bytes)
        if (data.size() == 33 && (data[0] == 0x02 || data[0] == 0x03)) {
            // Compressed format
            point_data_ = data;
            is_compressed_ = true;
        } else if (data.size() == 65 && data[0] == 0x04) {
            // Uncompressed format
            point_data_ = data;
            is_compressed_ = false;
        } else {
            throw invalid_argument("Invalid public key format");
        }
    }
    
    validate_point();
}

void PublicKey::validate_point() const {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size())) {
        throw invalid_argument("Invalid public key point");
    }
}

PublicKey PublicKey::operator+(const PublicKey& other) const {
    // Parse both public keys
    secp256k1_pubkey pubkey1, pubkey2;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey1, point_data_.data(), point_data_.size()) ||
        !secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey2, other.point_data_.data(), other.point_data_.size())) {
        throw runtime_error("Failed to parse public keys for addition");
    }
    
    // Combine the public keys
    vector<const secp256k1_pubkey*> pubkeys = {&pubkey1, &pubkey2};
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(get_secp_context(), &result, pubkeys.data(), pubkeys.size())) {
        throw runtime_error("Failed to combine public keys");
    }
    
    // Serialize result
    vector<uint8_t> serialized(33);
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(get_secp_context(), serialized.data(), &output_len, &result, SECP256K1_EC_COMPRESSED);
    
    return PublicKey(serialized);
}

PublicKey PublicKey::operator-() const {
    // Negation in secp256k1 is done by flipping the y-coordinate parity
    vector<uint8_t> serialized = serialize(true);  // Get compressed format
    
    if (serialized.size() == 33) {
        // Flip the parity byte (0x02 <-> 0x03)
        if (serialized[0] == 0x02) {
            serialized[0] = 0x03;
        } else if (serialized[0] == 0x03) {
            serialized[0] = 0x02;
        } else {
            throw runtime_error("Invalid compressed public key format for negation");
        }
    }
    
    return PublicKey(serialized);
}

PublicKey PublicKey::operator-(const PublicKey& other) const {
    return *this + (-other);
}

PublicKey PublicKey::mult(const PrivateKey& scalar) const {
    return tweak_mul(scalar.raw_value());
}

PublicKey PublicKey::tweak_mul(const cpp_int& scalar) const {
    // Convert scalar to 32-byte array
    vector<uint8_t> scalar_bytes(32, 0);
    cpp_int temp = scalar % secp256k1_const::CURVE_ORDER;
    
    for (int i = 31; i >= 0; --i) {
        scalar_bytes[i] = static_cast<uint8_t>(temp & 0xFF);
        temp >>= 8;
    }
    
    // Parse public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size())) {
        throw runtime_error("Failed to parse public key for multiplication");
    }
    
    // Multiply by scalar
    if (!secp256k1_ec_pubkey_tweak_mul(get_secp_context(), &pubkey, scalar_bytes.data())) {
        throw runtime_error("Failed to multiply public key by scalar");
    }
    
    // Serialize result
    vector<uint8_t> serialized(33);
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(get_secp_context(), serialized.data(), &output_len, &pubkey, SECP256K1_EC_COMPRESSED);
    
    return PublicKey(serialized);
}

PublicKey PublicKey::tweak_add(const cpp_int& scalar) const {
    // Convert scalar to 32-byte array
    vector<uint8_t> scalar_bytes(32, 0);
    cpp_int temp = scalar % secp256k1_const::CURVE_ORDER;
    
    for (int i = 31; i >= 0; --i) {
        scalar_bytes[i] = static_cast<uint8_t>(temp & 0xFF);
        temp >>= 8;
    }
    
    // Parse public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size())) {
        throw runtime_error("Failed to parse public key for tweak addition");
    }
    
    // Add scalar*G
    if (!secp256k1_ec_pubkey_tweak_add(get_secp_context(), &pubkey, scalar_bytes.data())) {
        throw runtime_error("Failed to add scalar to public key");
    }
    
    // Serialize result
    vector<uint8_t> serialized(33);
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(get_secp_context(), serialized.data(), &output_len, &pubkey, SECP256K1_EC_COMPRESSED);
    
    return PublicKey(serialized);
}

bool PublicKey::operator==(const PublicKey& other) const {
    // Compare the raw point data (convert both to same format first)
    vector<uint8_t> data1 = to_data();
    vector<uint8_t> data2 = other.to_data();
    return data1 == data2;
}

bool PublicKey::operator<(const PublicKey& other) const {
    // Compare the raw point data for ordering
    vector<uint8_t> data1 = to_data();
    vector<uint8_t> data2 = other.to_data();
    return data1 < data2;
}

vector<uint8_t> PublicKey::serialize(bool compressed) const {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size())) {
        throw runtime_error("Failed to parse public key for serialization");
    }
    
    if (compressed) {
        vector<uint8_t> result(33);
        size_t output_len = 33;
        secp256k1_ec_pubkey_serialize(get_secp_context(), result.data(), &output_len, &pubkey, SECP256K1_EC_COMPRESSED);
        return result;
    } else {
        vector<uint8_t> result(65);
        size_t output_len = 65;
        secp256k1_ec_pubkey_serialize(get_secp_context(), result.data(), &output_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        return result;
    }
}

string PublicKey::to_hex(bool compressed) const {
    return secp_utils::bytes_to_hex(serialize(compressed));
}

vector<uint8_t> PublicKey::to_data() const {
    // Return 64-byte internal secp256k1 representation for nutshell compatibility
    // This matches exactly what nutshell's pk.public_key.data returns
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size())) {
        throw runtime_error("Failed to parse public key for to_data()");
    }
    
    // Extract the 64-byte internal representation
    vector<uint8_t> result(64);
    memcpy(result.data(), &pubkey.data, 64);
    
    return result;
}

bool PublicKey::verify(const vector<uint8_t>& message, const vector<uint8_t>& signature) const {
    // Hash the message
    vector<uint8_t> hash(32);
    SHA256(message.data(), message.size(), hash.data());
    
    // Parse public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size())) {
        return false;
    }
    
    // Parse signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(get_secp_context(), &sig, signature.data(), signature.size())) {
        return false;
    }
    
    // Verify signature
    return secp256k1_ecdsa_verify(get_secp_context(), &sig, hash.data(), &pubkey) == 1;
}

bool PublicKey::is_valid() const {
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(get_secp_context(), &pubkey, point_data_.data(), point_data_.size());
}

PublicKey PublicKey::combine(const vector<PublicKey>& pubkeys) {
    if (pubkeys.empty()) {
        throw invalid_argument("Cannot combine empty list of public keys");
    }
    
    vector<secp256k1_pubkey> parsed_keys(pubkeys.size());
    vector<const secp256k1_pubkey*> key_ptrs(pubkeys.size());
    
    // Parse all public keys
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        if (!secp256k1_ec_pubkey_parse(get_secp_context(), &parsed_keys[i], 
                                       pubkeys[i].point_data_.data(), pubkeys[i].point_data_.size())) {
            throw runtime_error("Failed to parse public key for combination");
        }
        key_ptrs[i] = &parsed_keys[i];
    }
    
    // Combine all keys
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(get_secp_context(), &result, key_ptrs.data(), key_ptrs.size())) {
        throw runtime_error("Failed to combine public keys");
    }
    
    // Serialize result
    vector<uint8_t> serialized(33);
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(get_secp_context(), serialized.data(), &output_len, &result, SECP256K1_EC_COMPRESSED);
    
    return PublicKey(serialized);
}

} // namespace cashu::core::crypto