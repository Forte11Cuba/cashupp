// NUTSHELL COMPATIBILITY: cashu/core/crypto/b_dhke.py
// Complete Blind Diffie-Hellman Key Exchange implementation providing C++ interface compatible with nutshell

#include "cashu/core/crypto/b_dhke.hpp"
#include <openssl/sha.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::crypto {

// Domain separator for hash-to-curve operations
const vector<uint8_t> DOMAIN_SEPARATOR = {
    0x53, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6b, 0x31, 0x5f, 0x48, 0x61, 
    0x73, 0x68, 0x54, 0x6f, 0x43, 0x75, 0x72, 0x76, 0x65, 0x5f, 0x43, 0x61, 
    0x73, 0x68, 0x75, 0x5f
}; // "Secp256k1_HashToCurve_Cashu_"

//=============================================================================
// Utility Functions
//=============================================================================

namespace {
    vector<uint8_t> sha256(const vector<uint8_t>& data) {
        vector<uint8_t> hash(32);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }
    
    vector<uint8_t> uint32_to_le_bytes(uint32_t value) {
        vector<uint8_t> bytes(4);
        bytes[0] = value & 0xFF;
        bytes[1] = (value >> 8) & 0xFF;
        bytes[2] = (value >> 16) & 0xFF;
        bytes[3] = (value >> 24) & 0xFF;
        return bytes;
    }
    
    vector<uint8_t> concat_vectors(const vector<uint8_t>& a, const vector<uint8_t>& b) {
        vector<uint8_t> result;
        result.reserve(a.size() + b.size());
        result.insert(result.end(), a.begin(), a.end());
        result.insert(result.end(), b.begin(), b.end());
        return result;
    }
}

//=============================================================================
// Hash-to-Curve Implementation
//=============================================================================

PublicKey hash_to_curve(const vector<uint8_t>& message) {
    // Hash message with domain separator
    vector<uint8_t> domain_and_message = concat_vectors(DOMAIN_SEPARATOR, message);
    vector<uint8_t> msg_to_hash = sha256(domain_and_message);
    
    uint32_t counter = 0;
    while (counter < (1 << 16)) {  // 2^16 iterations max
        // Append counter in little endian format
        vector<uint8_t> counter_bytes = uint32_to_le_bytes(counter);
        vector<uint8_t> hash_input = concat_vectors(msg_to_hash, counter_bytes);
        vector<uint8_t> hash_output = sha256(hash_input);
        
        try {
            // Try to create point with 0x02 prefix (compressed format)
            vector<uint8_t> point_data(33);
            point_data[0] = 0x02;  // Compressed point prefix
            copy(hash_output.begin(), hash_output.end(), point_data.begin() + 1);
            
            return PublicKey(point_data, false);  // Standard compressed format
        } catch (const exception&) {
            // Point doesn't lie on curve, try next counter
            counter++;
        }
    }
    
    throw runtime_error("No valid point found after 2^16 iterations");
}

PublicKey hash_to_curve(const string& message) {
    vector<uint8_t> message_bytes(message.begin(), message.end());
    return hash_to_curve(message_bytes);
}

//=============================================================================
// BDHKE Protocol Implementation
//=============================================================================

tuple<PublicKey, PrivateKey> step1_alice(
    const string& secret_msg,
    const optional<PrivateKey>& blinding_factor
) {
    // Y = hash_to_curve(secret_message)
    PublicKey Y = hash_to_curve(secret_msg);
    
    // r = random blinding factor (or provided one)
    PrivateKey r = blinding_factor ? *blinding_factor : PrivateKey();
    
    // B' = Y + r*G = Y + r.pubkey()
    PublicKey B_ = Y + r.pubkey();
    
    return make_tuple(B_, r);
}

tuple<PublicKey, PrivateKey, PrivateKey> step2_bob(
    const PublicKey& B_,
    const PrivateKey& a
) {
    // C' = a*B'
    PublicKey C_ = B_.mult(a);
    
    // Generate DLEQ proof
    auto [e, s] = step2_bob_dleq(B_, a);
    
    return make_tuple(C_, e, s);
}

PublicKey step3_alice(
    const PublicKey& C_,
    const PrivateKey& r,
    const PublicKey& A
) {
    // C = C' - r*A
    PublicKey r_times_A = A.mult(r);
    PublicKey C = C_ - r_times_A;
    
    return C;
}

bool verify(
    const PrivateKey& a,
    const PublicKey& C,
    const string& secret_msg
) {
    // Y = hash_to_curve(secret_msg)
    PublicKey Y = hash_to_curve(secret_msg);
    
    // Check if C == a*Y
    PublicKey a_times_Y = Y.mult(a);
    bool valid = (C == a_times_Y);
    
    // BEGIN: BACKWARDS COMPATIBILITY < 0.15.1
    if (!valid) {
        valid = verify_deprecated(a, C, secret_msg);
    }
    // END: BACKWARDS COMPATIBILITY < 0.15.1
    
    return valid;
}

//=============================================================================
// DLEQ Proof Implementation
//=============================================================================

vector<uint8_t> hash_e(
    const PublicKey& R1,
    const PublicKey& R2,
    const PublicKey& A,
    const PublicKey& C_
) {
    // Concatenate all public keys in uncompressed format
    string e_string;
    
    vector<PublicKey> pubkeys = {R1, R2, A, C_};
    for (const auto& pk : pubkeys) {
        vector<uint8_t> uncompressed = pk.serialize(false);  // Uncompressed format
        
        // Convert to hex string (lowercase like nutshell)
        ostringstream oss;
        for (uint8_t byte : uncompressed) {
            oss << setfill('0') << setw(2) << std::hex << static_cast<int>(byte);
        }
        e_string += oss.str();
    }
    
    // Hash the concatenated string
    vector<uint8_t> e_bytes(e_string.begin(), e_string.end());
    return sha256(e_bytes);
}

tuple<PrivateKey, PrivateKey> step2_bob_dleq(
    const PublicKey& B_,
    const PrivateKey& a,
    const vector<uint8_t>& p_bytes
) {
    PrivateKey p;
    if (!p_bytes.empty()) {
        // Deterministic p for testing
        p = PrivateKey(p_bytes);
    } else {
        // Generate random p
        p = PrivateKey();
    }
    
    // R1 = p*G
    PublicKey R1 = p.pubkey();
    
    // R2 = p*B'
    PublicKey R2 = B_.mult(p);
    
    // C' = a*B'
    PublicKey C_ = B_.mult(a);
    
    // A = a*G
    PublicKey A = a.pubkey();
    
    // e = hash(R1, R2, A, C')
    vector<uint8_t> e_bytes = hash_e(R1, R2, A, C_);
    PrivateKey e(e_bytes);
    
    // s = p + e*a using secp256k1 tweak operations (same as nutshell)
    // nutshell: s = p.tweak_add(a.tweak_mul(e))
    PrivateKey a_times_e = a.tweak_mul(e.raw_value());  // a.tweak_mul(e)
    PrivateKey s = p.tweak_add(a_times_e.raw_value());  // p.tweak_add(a*e)
    
    return make_tuple(e, s);
}

bool alice_verify_dleq(
    const PublicKey& B_,
    const PublicKey& C_,
    const PrivateKey& e,
    const PrivateKey& s,
    const PublicKey& A
) {
    // R1 = s*G - e*A
    PublicKey s_times_G = s.pubkey();
    PublicKey e_times_A = A.mult(e);
    PublicKey R1 = s_times_G - e_times_A;
    
    // R2 = s*B' - e*C'
    PublicKey s_times_B_ = B_.mult(s);
    PublicKey e_times_C_ = C_.mult(e);
    PublicKey R2 = s_times_B_ - e_times_C_;
    
    // Verify e == hash(R1, R2, A, C')
    vector<uint8_t> computed_e = hash_e(R1, R2, A, C_);
    vector<uint8_t> provided_e = e.serialize();
    
    return computed_e == provided_e;
}

bool carol_verify_dleq(
    const string& secret_msg,
    const PrivateKey& r,
    const PublicKey& C,
    const PrivateKey& e,
    const PrivateKey& s,
    const PublicKey& A
) {
    // Y = hash_to_curve(secret_msg)
    PublicKey Y = hash_to_curve(secret_msg);
    
    // C' = C + r*A
    PublicKey r_times_A = A.mult(r);
    PublicKey C_ = C + r_times_A;
    
    // B' = Y + r*G
    PublicKey r_times_G = r.pubkey();
    PublicKey B_ = Y + r_times_G;
    
    // Verify using Alice's verification
    bool valid = alice_verify_dleq(B_, C_, e, s, A);
    
    // BEGIN: BACKWARDS COMPATIBILITY < 0.15.1
    if (!valid) {
        valid = carol_verify_dleq_deprecated(secret_msg, r, C, e, s, A);
    }
    // END: BACKWARDS COMPATIBILITY < 0.15.1
    
    return valid;
}

//=============================================================================
// Deprecated Functions (Backwards Compatibility)
//=============================================================================

PublicKey hash_to_curve_deprecated(const vector<uint8_t>& message) {
    vector<uint8_t> msg_to_hash = message;
    
    while (true) {
        vector<uint8_t> hash_output = sha256(msg_to_hash);
        
        try {
            // Try to create point with 0x02 prefix
            vector<uint8_t> point_data(33);
            point_data[0] = 0x02;
            copy(hash_output.begin(), hash_output.end(), point_data.begin() + 1);
            
            return PublicKey(point_data, false);
        } catch (const exception&) {
            // Point doesn't lie on curve, hash again
            msg_to_hash = hash_output;
        }
    }
}

tuple<PublicKey, PrivateKey> step1_alice_deprecated(
    const string& secret_msg,
    const optional<PrivateKey>& blinding_factor
) {
    vector<uint8_t> message_bytes(secret_msg.begin(), secret_msg.end());
    PublicKey Y = hash_to_curve_deprecated(message_bytes);
    
    PrivateKey r = blinding_factor ? *blinding_factor : PrivateKey();
    PublicKey B_ = Y + r.pubkey();
    
    return make_tuple(B_, r);
}

bool verify_deprecated(
    const PrivateKey& a,
    const PublicKey& C,
    const string& secret_msg
) {
    vector<uint8_t> message_bytes(secret_msg.begin(), secret_msg.end());
    PublicKey Y = hash_to_curve_deprecated(message_bytes);
    PublicKey a_times_Y = Y.mult(a);
    
    return C == a_times_Y;
}

bool carol_verify_dleq_deprecated(
    const string& secret_msg,
    const PrivateKey& r,
    const PublicKey& C,
    const PrivateKey& e,
    const PrivateKey& s,
    const PublicKey& A
) {
    vector<uint8_t> message_bytes(secret_msg.begin(), secret_msg.end());
    PublicKey Y = hash_to_curve_deprecated(message_bytes);
    
    PublicKey r_times_A = A.mult(r);
    PublicKey C_ = C + r_times_A;
    
    PublicKey r_times_G = r.pubkey();
    PublicKey B_ = Y + r_times_G;
    
    return alice_verify_dleq(B_, C_, e, s, A);
}

} // namespace cashu::core::crypto