#include "cashu/core/crypto/bip39.hpp"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <filesystem>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::crypto {

//=============================================================================
// Private Helper Functions
//=============================================================================

string BIP39::get_wordlist_path() {
    // Try compile-time path first (set by CMake)
    #ifdef BIP39_WORDLIST_PATH
        return string(BIP39_WORDLIST_PATH) + "/english.txt";
    #else
        // Fallback to relative path from build directory
        return "../resources/bip39/english.txt";
    #endif
}

vector<bool> BIP39::calculate_checksum(const vector<uint8_t>& entropy) {
    // Calculate SHA256 hash of entropy
    vector<uint8_t> hash(32);
    SHA256(entropy.data(), entropy.size(), hash.data());
    
    // Calculate number of checksum bits (entropy_length_in_bits / 32)
    int checksum_bits = (entropy.size() * 8) / 32;
    
    // Extract checksum bits from the first byte(s) of hash
    vector<bool> checksum;
    for (int i = 0; i < checksum_bits; ++i) {
        int byte_index = i / 8;
        int bit_index = 7 - (i % 8); // MSB first
        bool bit = (hash[byte_index] >> bit_index) & 1;
        checksum.push_back(bit);
    }
    
    return checksum;
}

vector<bool> BIP39::bytes_to_bits(const vector<uint8_t>& bytes) {
    vector<bool> bits;
    for (uint8_t byte : bytes) {
        for (int i = 7; i >= 0; --i) { // MSB first
            bits.push_back((byte >> i) & 1);
        }
    }
    return bits;
}

vector<uint8_t> BIP39::bits_to_bytes(const vector<bool>& bits) {
    if (bits.size() % 8 != 0) {
        throw invalid_argument("Bit array length must be multiple of 8");
    }
    
    vector<uint8_t> bytes;
    for (size_t i = 0; i < bits.size(); i += 8) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; ++j) {
            if (bits[i + j]) {
                byte |= (1 << (7 - j)); // MSB first
            }
        }
        bytes.push_back(byte);
    }
    return bytes;
}

int BIP39::find_word_index(const string& word, const vector<string>& wordlist) {
    auto it = find(wordlist.begin(), wordlist.end(), word);
    if (it == wordlist.end()) {
        return -1;
    }
    return distance(wordlist.begin(), it);
}

//=============================================================================
// Public API Implementation
//=============================================================================

vector<string> BIP39::load_english_wordlist() {
    string path = get_wordlist_path();
    ifstream file(path);
    
    if (!file.is_open()) {
        throw runtime_error("Cannot open BIP39 wordlist file: " + path);
    }
    
    vector<string> wordlist;
    string word;
    
    while (getline(file, word)) {
        // Remove any trailing whitespace/newlines
        word.erase(word.find_last_not_of(" \t\r\n") + 1);
        if (!word.empty()) {
            wordlist.push_back(word);
        }
    }
    
    if (wordlist.size() != 2048) {
        throw runtime_error("Invalid BIP39 wordlist: expected 2048 words, got " + 
                          to_string(wordlist.size()));
    }
    
    return wordlist;
}

string BIP39::entropy_to_mnemonic(const vector<uint8_t>& entropy) {
    // Validate entropy length
    if (entropy.size() < 16 || entropy.size() > 32 || entropy.size() % 4 != 0) {
        throw invalid_argument("Entropy must be 16, 20, 24, 28, or 32 bytes");
    }
    
    // Load wordlist
    vector<string> wordlist = load_english_wordlist();
    
    // Convert entropy to bits
    vector<bool> entropy_bits = bytes_to_bits(entropy);
    
    // Calculate and append checksum
    vector<bool> checksum = calculate_checksum(entropy);
    entropy_bits.insert(entropy_bits.end(), checksum.begin(), checksum.end());
    
    // Split into 11-bit groups and convert to words
    vector<string> words;
    for (size_t i = 0; i < entropy_bits.size(); i += 11) {
        // Extract 11 bits
        int word_index = 0;
        for (int j = 0; j < 11 && (i + j) < entropy_bits.size(); ++j) {
            if (entropy_bits[i + j]) {
                word_index |= (1 << (10 - j)); // MSB first
            }
        }
        
        if (word_index >= 2048) {
            throw runtime_error("Invalid word index: " + to_string(word_index));
        }
        
        words.push_back(wordlist[word_index]);
    }
    
    // Join words with spaces
    ostringstream oss;
    for (size_t i = 0; i < words.size(); ++i) {
        if (i > 0) oss << " ";
        oss << words[i];
    }
    
    return oss.str();
}

vector<uint8_t> BIP39::mnemonic_to_entropy(const string& mnemonic) {
    // Load wordlist
    vector<string> wordlist = load_english_wordlist();
    
    // Split mnemonic into words
    istringstream iss(mnemonic);
    vector<string> words;
    string word;
    while (iss >> word) {
        words.push_back(word);
    }
    
    // Validate word count
    if (words.size() % 3 != 0 || words.size() < 12 || words.size() > 24) {
        throw invalid_argument("Invalid mnemonic length: must be 12, 15, 18, 21, or 24 words");
    }
    
    // Convert words to bit array
    vector<bool> bits;
    for (const string& w : words) {
        int index = find_word_index(w, wordlist);
        if (index == -1) {
            throw invalid_argument("Invalid word in mnemonic: " + w);
        }
        
        // Convert index to 11 bits (MSB first)
        for (int i = 10; i >= 0; --i) {
            bits.push_back((index >> i) & 1);
        }
    }
    
    // Calculate entropy and checksum lengths
    int total_bits = bits.size();
    int checksum_bits = total_bits / 33; // 1 checksum bit per 32 entropy bits
    int entropy_bits = total_bits - checksum_bits;
    
    // Extract entropy and checksum
    vector<bool> entropy_bit_array(bits.begin(), bits.begin() + entropy_bits);
    vector<bool> provided_checksum(bits.begin() + entropy_bits, bits.end());
    
    // Convert entropy bits to bytes
    vector<uint8_t> entropy = bits_to_bytes(entropy_bit_array);
    
    // Validate checksum
    vector<bool> calculated_checksum = calculate_checksum(entropy);
    if (provided_checksum != calculated_checksum) {
        throw invalid_argument("Invalid mnemonic: checksum mismatch");
    }
    
    return entropy;
}

bool BIP39::validate_mnemonic(const string& mnemonic) {
    try {
        mnemonic_to_entropy(mnemonic);
        return true;
    } catch (const exception&) {
        return false;
    }
}

string BIP39::generate_mnemonic(int entropy_bits) {
    // Validate entropy bits
    if (entropy_bits % 32 != 0 || entropy_bits < 128 || entropy_bits > 256) {
        throw invalid_argument("Entropy bits must be 128, 160, 192, 224, or 256");
    }
    
    // Generate random entropy
    int entropy_bytes = entropy_bits / 8;
    vector<uint8_t> entropy(entropy_bytes);
    
    if (RAND_bytes(entropy.data(), entropy_bytes) != 1) {
        throw runtime_error("Failed to generate random entropy");
    }
    
    // Convert to mnemonic
    return entropy_to_mnemonic(entropy);
}

} // namespace cashu::core::crypto