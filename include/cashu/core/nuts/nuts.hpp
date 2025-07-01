#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/nuts/nuts.py
// NUT (Notation for Tokens) specification constants
// Reference: https://github.com/cashubtc/nuts/

namespace cashu::core::nuts {

// NUT Specification Numbers
// These constants define the NUT specification numbers used throughout the Cashu protocol

constexpr int SWAP_NUT = 3;                      // NUT-03: Swap tokens
constexpr int MINT_NUT = 4;                      // NUT-04: Mint tokens  
constexpr int MELT_NUT = 5;                      // NUT-05: Melt tokens
constexpr int INFO_NUT = 6;                      // NUT-06: Mint info
constexpr int STATE_NUT = 7;                     // NUT-07: Proof state check
constexpr int FEE_RETURN_NUT = 8;                // NUT-08: Fee return
constexpr int RESTORE_NUT = 9;                   // NUT-09: Restore signatures
constexpr int SCRIPT_NUT = 10;                   // NUT-10: Spending conditions
constexpr int P2PK_NUT = 11;                     // NUT-11: Pay-to-Public-Key
constexpr int DLEQ_NUT = 12;                     // NUT-12: DLEQ proofs
constexpr int DETERMINSTIC_SECRETS_NUT = 13;     // NUT-13: Deterministic secrets
constexpr int HTLC_NUT = 14;                     // NUT-14: Hash Time Lock Contracts
constexpr int MPP_NUT = 15;                      // NUT-15: Multi-Path Payments
constexpr int WEBSOCKETS_NUT = 17;               // NUT-17: WebSocket subscriptions
constexpr int CACHE_NUT = 19;                    // NUT-19: Cached signatures
constexpr int MINT_QUOTE_SIGNATURE_NUT = 20;     // NUT-20: Mint quote signatures
constexpr int CLEAR_AUTH_NUT = 21;               // NUT-21: Clear text authentication
constexpr int BLIND_AUTH_NUT = 22;               // NUT-22: Blind authentication
constexpr int METHOD_BOLT11_NUT = 23;            // NUT-23: BOLT11 method
constexpr int HTTP_402_NUT = 24;                 // NUT-24: HTTP 402 Payment Required

} // namespace cashu::core::nuts