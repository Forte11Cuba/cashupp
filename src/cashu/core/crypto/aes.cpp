#include "cashu/core/crypto/aes.hpp"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

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
    
    // Base64 alphabet for URL-safe encoding
    const string base64_urlsafe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    string encode_base64_standard(const vector<uint8_t>& data) {
        string encoded;
        const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t val = (data[i] << 16);
            if (i + 1 < data.size()) val |= (data[i + 1] << 8);
            if (i + 2 < data.size()) val |= data[i + 2];
            
            encoded += chars[(val >> 18) & 0x3F];
            encoded += chars[(val >> 12) & 0x3F];
            encoded += (i + 1 < data.size()) ? chars[(val >> 6) & 0x3F] : '=';
            encoded += (i + 2 < data.size()) ? chars[val & 0x3F] : '=';
        }
        
        return encoded;
    }
    
    vector<uint8_t> decode_base64_standard(const string& encoded) {
        vector<uint8_t> result;
        
        // Create lookup table
        int lookup[256];
        fill(lookup, lookup + 256, -1);
        for (int i = 0; i < 64; ++i) {
            lookup[static_cast<unsigned char>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i])] = i;
        }
        
        for (size_t i = 0; i < encoded.length(); i += 4) {
            if (i + 3 >= encoded.length()) break;
            
            int a = lookup[static_cast<unsigned char>(encoded[i])];
            int b = lookup[static_cast<unsigned char>(encoded[i + 1])];
            int c = lookup[static_cast<unsigned char>(encoded[i + 2])];
            int d = lookup[static_cast<unsigned char>(encoded[i + 3])];
            
            if (a == -1 || b == -1) break;
            
            result.push_back((a << 2) | (b >> 4));
            
            if (encoded[i + 2] != '=' && c != -1) {
                result.push_back(((b & 0x0F) << 4) | (c >> 2));
            }
            
            if (encoded[i + 3] != '=' && d != -1) {
                result.push_back(((c & 0x03) << 6) | d);
            }
        }
        
        return result;
    }
}

//=============================================================================
// AESCipher Implementation
//=============================================================================

AESCipher::AESCipher(const string& key, const string& description) 
    : key_(key), description_(description) {
    if (key_.empty()) {
        throw invalid_argument("AES key cannot be empty");
    }
}

string AESCipher::encrypt(const vector<uint8_t>& message) {
    // Generate random 8-byte salt
    vector<uint8_t> salt = generate_random_bytes(8);
    
    // Derive key and IV using crypto-js compatible method
    vector<uint8_t> key_data(key_.begin(), key_.end());
    vector<uint8_t> key_iv = bytes_to_key(key_data, salt, 48); // 32 bytes key + 16 bytes IV
    
    vector<uint8_t> aes_key(key_iv.begin(), key_iv.begin() + 32);
    vector<uint8_t> iv(key_iv.begin() + 32, key_iv.end());
    
    // Apply manual PKCS7 padding (like nutshell does)
    vector<uint8_t> padded_message = pad(message);
    
    // Encrypt with AES-256-CBC (disable automatic padding since we do it manually)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create cipher context");
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption");
    }
    
    // Disable automatic padding since we do it manually
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to disable automatic padding");
    }
    
    vector<uint8_t> encrypted_data;
    encrypted_data.resize(padded_message.size() + AES_BLOCK_SIZE);
    
    int len = 0;
    int total_len = 0;
    
    if (EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, padded_message.data(), padded_message.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to encrypt data");
    }
    total_len += len;
    
    if (EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to finalize encryption");
    }
    total_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    encrypted_data.resize(total_len);
    
    // Build final output: "Salted__" + salt + encrypted_data
    vector<uint8_t> final_output;
    final_output.reserve(8 + 8 + encrypted_data.size());
    
    // Add "Salted__" header
    final_output.insert(final_output.end(), SALT_HEADER, SALT_HEADER + 8);
    
    // Add salt
    final_output.insert(final_output.end(), salt.begin(), salt.end());
    
    // Add encrypted data
    final_output.insert(final_output.end(), encrypted_data.begin(), encrypted_data.end());
    
    // Encode as base64-urlsafe
    return encode_base64_urlsafe(final_output);
}

string AESCipher::encrypt(const string& message) {
    vector<uint8_t> message_bytes(message.begin(), message.end());
    return encrypt(message_bytes);
}

string AESCipher::decrypt(const string& encrypted) {
    // Decode base64-urlsafe
    vector<uint8_t> encrypted_data = decode_base64_urlsafe(encrypted);
    
    // Verify minimum length: "Salted__" (8) + salt (8) + at least 1 block (16) = 32 bytes
    if (encrypted_data.size() < 32) {
        throw invalid_argument("Encrypted data too short");
    }
    
    // Verify "Salted__" header
    if (memcmp(encrypted_data.data(), SALT_HEADER, 8) != 0) {
        throw invalid_argument("Invalid encrypted data format: missing 'Salted__' header");
    }
    
    // Extract salt (bytes 8-15)
    vector<uint8_t> salt(encrypted_data.begin() + 8, encrypted_data.begin() + 16);
    
    // Extract encrypted payload (bytes 16+)
    vector<uint8_t> payload(encrypted_data.begin() + 16, encrypted_data.end());
    
    // Derive key and IV
    vector<uint8_t> key_data(key_.begin(), key_.end());
    vector<uint8_t> key_iv = bytes_to_key(key_data, salt, 48);
    
    vector<uint8_t> aes_key(key_iv.begin(), key_iv.begin() + 32);
    vector<uint8_t> iv(key_iv.begin() + 32, key_iv.end());
    
    // Decrypt with AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create cipher context");
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption");
    }
    
    // Disable automatic padding since we handle it manually
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to disable automatic padding");
    }
    
    vector<uint8_t> decrypted_data;
    decrypted_data.resize(payload.size() + AES_BLOCK_SIZE);
    
    int len = 0;
    int total_len = 0;
    
    if (EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, payload.data(), payload.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to decrypt data");
    }
    total_len += len;
    
    if (EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Wrong passphrase or corrupted data");
    }
    total_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    decrypted_data.resize(total_len);
    
    // Remove PKCS7 padding
    vector<uint8_t> unpadded_data = unpad(decrypted_data);
    
    // Convert to string
    return string(unpadded_data.begin(), unpadded_data.end());
}

//=============================================================================
// Private Helper Methods
//=============================================================================

vector<uint8_t> AESCipher::pad(const vector<uint8_t>& data) {
    // PKCS7 padding
    size_t padding_length = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    
    vector<uint8_t> padded = data;
    padded.resize(data.size() + padding_length);
    
    // Fill padding bytes with padding length value
    for (size_t i = data.size(); i < padded.size(); ++i) {
        padded[i] = static_cast<uint8_t>(padding_length);
    }
    
    return padded;
}

vector<uint8_t> AESCipher::unpad(const vector<uint8_t>& data) {
    if (data.empty()) {
        throw runtime_error("Cannot unpad empty data");
    }
    
    // Get padding length from last byte
    uint8_t padding_length = data.back();
    
    // Validate padding length
    if (padding_length == 0 || padding_length > BLOCK_SIZE || padding_length > data.size()) {
        throw runtime_error("Invalid padding");
    }
    
    // Verify all padding bytes have correct value
    for (size_t i = data.size() - padding_length; i < data.size(); ++i) {
        if (data[i] != padding_length) {
            throw runtime_error("Invalid padding bytes");
        }
    }
    
    // Return data without padding
    return vector<uint8_t>(data.begin(), data.end() - padding_length);
}

vector<uint8_t> AESCipher::bytes_to_key(const vector<uint8_t>& password, 
                                         const vector<uint8_t>& salt, 
                                         size_t output) {
    if (salt.size() != 8) {
        throw invalid_argument("Salt must be exactly 8 bytes");
    }
    
    // Combine password and salt
    vector<uint8_t> data = password;
    data.insert(data.end(), salt.begin(), salt.end());
    
    // First iteration: key = SHA256(password + salt)
    vector<uint8_t> key = sha256(data);
    vector<uint8_t> final_key = key;
    
    // Continue hashing until we have enough key material
    while (final_key.size() < output) {
        // Next iteration: key = SHA256(key + password + salt)
        vector<uint8_t> next_input = key;
        next_input.insert(next_input.end(), data.begin(), data.end());
        key = sha256(next_input);
        final_key.insert(final_key.end(), key.begin(), key.end());
    }
    
    // Return exactly 'output' bytes
    final_key.resize(output);
    return final_key;
}

vector<uint8_t> AESCipher::generate_random_bytes(size_t count) {
    vector<uint8_t> random_bytes(count);
    
    if (RAND_bytes(random_bytes.data(), static_cast<int>(count)) != 1) {
        throw runtime_error("Failed to generate random bytes");
    }
    
    return random_bytes;
}

string AESCipher::encode_base64_urlsafe(const vector<uint8_t>& data) {
    // First encode as standard base64
    string base64 = encode_base64_standard(data);
    
    // Convert to URL-safe: replace + with -, / with _
    for (char& c : base64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    
    // Remove padding (= characters)
    auto pos = base64.find('=');
    if (pos != string::npos) {
        base64.erase(pos);
    }
    
    return base64;
}

vector<uint8_t> AESCipher::decode_base64_urlsafe(const string& encoded) {
    string base64 = encoded;
    
    // Convert from URL-safe: replace - with +, _ with /
    for (char& c : base64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    
    // Add padding if necessary
    while (base64.length() % 4 != 0) {
        base64 += '=';
    }
    
    return decode_base64_standard(base64);
}

//=============================================================================
// Utility Functions
//=============================================================================

namespace aes_utils {
    
    bool self_test() {
        try {
            // Test basic encryption/decryption
            AESCipher cipher("test_key_123");
            string original = "Hello, World! This is a test message for AES encryption.";
            
            string encrypted = cipher.encrypt(original);
            string decrypted = cipher.decrypt(encrypted);
            
            if (original != decrypted) {
                return false;
            }
            
            // Test with empty message
            string empty_encrypted = cipher.encrypt("");
            string empty_decrypted = cipher.decrypt(empty_encrypted);
            
            if (empty_decrypted != "") {
                return false;
            }
            
            // Test with binary data
            vector<uint8_t> binary_data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD};
            string binary_encrypted = cipher.encrypt(binary_data);
            string binary_decrypted = cipher.decrypt(binary_encrypted);
            
            vector<uint8_t> binary_result(binary_decrypted.begin(), binary_decrypted.end());
            if (binary_data != binary_result) {
                return false;
            }
            
            return true;
        } catch (const exception&) {
            return false;
        }
    }
    
    string generate_random_key(size_t length) {
        vector<uint8_t> random_bytes(length);
        
        if (RAND_bytes(random_bytes.data(), static_cast<int>(length)) != 1) {
            throw runtime_error("Failed to generate random key");
        }
        
        // Convert to hex string
        ostringstream oss;
        for (uint8_t byte : random_bytes) {
            oss << setfill('0') << setw(2) << hex << static_cast<int>(byte);
        }
        
        return oss.str();
    }
}

} // namespace cashu::core::crypto