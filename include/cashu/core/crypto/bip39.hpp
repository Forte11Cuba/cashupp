#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/crypto/bip39.py
// BIP39 mnemonic implementation - ENHANCEMENT beyond nutshell
// Nutshell uses external BIP32 library, cashuv2 provides complete BIP39 support

#include <string>
#include <vector>
#include <array>
#include <boost/multiprecision/cpp_int.hpp>

namespace cashu::core::crypto {
    using namespace boost::multiprecision;

/**
 * @brief BIP39 mnemonic utilities
 * 
 * Implementation of BIP39 standard for mnemonic code generation and validation.
 * Supports loading wordlists from files and converting between entropy and mnemonic phrases.
 * 
 * ENHANCEMENT: This provides complete BIP39 support beyond nutshell capabilities.
 * Nutshell relies on external bip32 library, cashuv2 implements full standard.
 */
class BIP39 {
public:
    /**
     * @brief Load BIP39 wordlist from file
     * 
     * Loads the English BIP39 wordlist from resources/bip39/english.txt
     * 
     * @return Vector containing all 2048 BIP39 words
     * @throws std::runtime_error if wordlist file cannot be loaded
     */
    static std::vector<std::string> load_english_wordlist();
    
    /**
     * @brief Convert entropy bytes to BIP39 mnemonic phrase
     * 
     * Converts entropy to mnemonic according to BIP39 specification:
     * 1. Add checksum bits (entropy_length/32 bits from SHA256)
     * 2. Split into 11-bit groups
     * 3. Map each group to wordlist index
     * 
     * @param entropy Raw entropy bytes (16, 20, 24, 28, or 32 bytes)
     * @return BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
     * @throws std::invalid_argument if entropy length is invalid
     */
    static std::string entropy_to_mnemonic(const std::vector<uint8_t>& entropy);
    
    /**
     * @brief Convert BIP39 mnemonic phrase to entropy bytes
     * 
     * Validates mnemonic and extracts original entropy:
     * 1. Validate all words exist in wordlist
     * 2. Convert words to 11-bit indices
     * 3. Extract entropy and checksum
     * 4. Validate checksum
     * 
     * @param mnemonic BIP39 mnemonic phrase
     * @return Original entropy bytes
     * @throws std::invalid_argument if mnemonic is invalid
     */
    static std::vector<uint8_t> mnemonic_to_entropy(const std::string& mnemonic);
    
    /**
     * @brief Validate BIP39 mnemonic phrase
     * 
     * Comprehensive validation:
     * - Check word count (12, 15, 18, 21, or 24)
     * - Verify all words exist in wordlist
     * - Validate checksum
     * 
     * @param mnemonic Mnemonic phrase to validate
     * @return True if mnemonic is valid
     */
    static bool validate_mnemonic(const std::string& mnemonic);
    
    /**
     * @brief Generate random BIP39 mnemonic phrase
     * 
     * Creates a new mnemonic with specified entropy:
     * - 128 bits = 12 words
     * - 160 bits = 15 words  
     * - 192 bits = 18 words
     * - 224 bits = 21 words
     * - 256 bits = 24 words
     * 
     * @param entropy_bits Bits of entropy (128, 160, 192, 224, or 256)
     * @return Generated BIP39 mnemonic phrase
     * @throws std::invalid_argument if entropy_bits is invalid
     */
    static std::string generate_mnemonic(int entropy_bits = 256);

private:
    /**
     * @brief Get path to wordlist file
     * 
     * Returns the full path to the English wordlist file.
     * Uses compile-time path from CMake or relative path.
     * 
     * @return Full path to english.txt
     */
    static std::string get_wordlist_path();
    
    /**
     * @brief Calculate checksum for entropy
     * 
     * Calculates BIP39 checksum by taking first (entropy_length/32) bits
     * from SHA256 hash of entropy.
     * 
     * @param entropy Entropy bytes
     * @return Checksum bits as vector<bool>
     */
    static std::vector<bool> calculate_checksum(const std::vector<uint8_t>& entropy);
    
    /**
     * @brief Convert bytes to bit array
     * 
     * @param bytes Input bytes
     * @return Bit representation as vector<bool>
     */
    static std::vector<bool> bytes_to_bits(const std::vector<uint8_t>& bytes);
    
    /**
     * @brief Convert bit array to bytes
     * 
     * @param bits Input bits (must be multiple of 8)
     * @return Byte representation
     */
    static std::vector<uint8_t> bits_to_bytes(const std::vector<bool>& bits);
    
    /**
     * @brief Find word index in wordlist
     * 
     * @param word Word to find
     * @param wordlist BIP39 wordlist
     * @return Index of word, or -1 if not found
     */
    static int find_word_index(const std::string& word, 
                              const std::vector<std::string>& wordlist);
};

} // namespace cashu::core::crypto