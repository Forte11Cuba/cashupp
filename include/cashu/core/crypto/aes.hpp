#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/crypto/aes.py
// AES-256-CBC encryption compatible with crypto-js and nutshell exactly
// 100% compatible key derivation, padding, and encoding

#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

namespace cashu::core::crypto {
    using namespace boost::multiprecision;

/**
 * @brief AES-256-CBC encryption/decryption compatible with crypto-js/aes.js
 * 
 * This class provides AES encryption and decryption functionality that is
 * 100% compatible with the JavaScript crypto-js library used in frontend
 * applications. It implements the same key derivation, padding, and encoding
 * as nutshell's AESCipher class.
 * 
 * NUTSHELL COMPATIBILITY: Matches cashu/core/crypto/aes.py exactly.
 * All methods use identical algorithms for cross-platform compatibility.
 * 
 * Frontend JavaScript usage:
 *   import AES from "crypto-js/aes.js";
 *   import Utf8 from "crypto-js/enc-utf8.js";
 *   AES.encrypt(decrypted, password).toString()
 *   AES.decrypt(encrypted, password).toString(Utf8);
 */
class AESCipher {
public:
    /**
     * @brief Construct AESCipher with encryption key
     * 
     * @param key String key for encryption/decryption
     * @param description Optional description for debugging
     */
    explicit AESCipher(const std::string& key, const std::string& description = "");

    /**
     * @brief Encrypt message using AES-256-CBC
     * 
     * Creates encrypted output in format compatible with crypto-js:
     * - Generates random 8-byte salt
     * - Derives key+IV using custom bytes_to_key function
     * - Encrypts with AES-256-CBC mode
     * - Returns base64-urlsafe encoded: "Salted__" + salt + encrypted_data
     * 
     * @param message Bytes to encrypt
     * @return Base64-urlsafe encoded encrypted string
     * @throws std::runtime_error if encryption fails
     */
    std::string encrypt(const std::vector<uint8_t>& message);
    
    /**
     * @brief Convenience overload for string messages
     * @param message String message to encrypt
     * @return Base64-urlsafe encoded encrypted string
     */
    std::string encrypt(const std::string& message);

    /**
     * @brief Decrypt AES-256-CBC encrypted string
     * 
     * Decrypts data encrypted by this class or crypto-js:
     * - Decodes base64-urlsafe input
     * - Verifies "Salted__" header
     * - Extracts salt and derives key+IV
     * - Decrypts with AES-256-CBC mode
     * - Removes PKCS7 padding
     * 
     * @param encrypted Base64-urlsafe encoded encrypted data
     * @return Decrypted string
     * @throws std::invalid_argument if format is invalid
     * @throws std::runtime_error if decryption fails or wrong passphrase
     */
    std::string decrypt(const std::string& encrypted);

private:
    std::string key_;
    std::string description_;
    
    // AES block size (128 bits = 16 bytes)
    static constexpr size_t BLOCK_SIZE = 16;
    
    // Salt header used by crypto-js
    static constexpr char SALT_HEADER[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};

    /**
     * @brief Apply PKCS7 padding to data
     * 
     * Pads data to block boundary using PKCS7 standard:
     * - Calculate padding length needed
     * - Append padding_length bytes, each with value = padding_length
     * 
     * @param data Data to pad
     * @return Padded data
     */
    std::vector<uint8_t> pad(const std::vector<uint8_t>& data);

    /**
     * @brief Remove PKCS7 padding from data
     * 
     * Removes PKCS7 padding:
     * - Read last byte to get padding length
     * - Verify padding is valid
     * - Remove padding bytes
     * 
     * @param data Padded data
     * @return Unpadded data
     * @throws std::runtime_error if padding is invalid
     */
    std::vector<uint8_t> unpad(const std::vector<uint8_t>& data);

    /**
     * @brief Derive key and IV from password and salt (crypto-js compatible)
     * 
     * Implements the same key derivation as crypto-js and nutshell:
     * 1. key = SHA256(password + salt)
     * 2. While len(final_key) < output: key = SHA256(key + password + salt), final_key += key
     * 3. Return first 'output' bytes
     * 
     * This is based on OpenSSL's EVP_BytesToKey function.
     * 
     * @param password Password bytes
     * @param salt 8-byte salt
     * @param output Number of output bytes (32 for key + 16 for IV = 48)
     * @return Derived key material (first 32 bytes = key, next 16 bytes = IV)
     */
    std::vector<uint8_t> bytes_to_key(const std::vector<uint8_t>& password, 
                                      const std::vector<uint8_t>& salt, 
                                      size_t output = 48);

    /**
     * @brief Generate cryptographically secure random bytes
     * @param count Number of bytes to generate
     * @return Random bytes
     */
    std::vector<uint8_t> generate_random_bytes(size_t count);

    /**
     * @brief Encode bytes to base64-urlsafe format
     * @param data Bytes to encode
     * @return Base64-urlsafe encoded string
     */
    std::string encode_base64_urlsafe(const std::vector<uint8_t>& data);

    /**
     * @brief Decode base64-urlsafe format to bytes
     * @param encoded Base64-urlsafe encoded string
     * @return Decoded bytes
     * @throws std::invalid_argument if encoding is invalid
     */
    std::vector<uint8_t> decode_base64_urlsafe(const std::string& encoded);
};

/**
 * @brief Utility functions for AES operations
 */
namespace aes_utils {
    /**
     * @brief Verify that AES implementation is working correctly
     * 
     * Runs self-tests to ensure AES encryption/decryption produces
     * expected results and is compatible with reference vectors.
     * 
     * @return True if all tests pass
     */
    bool self_test();

    /**
     * @brief Generate a random encryption key
     * 
     * Generates a cryptographically secure random key suitable
     * for use with AESCipher.
     * 
     * @param length Key length in characters (default: 32)
     * @return Random key string
     */
    std::string generate_random_key(size_t length = 32);
}

} // namespace cashu::core::crypto