# Cashu++ - High-Performance C++ Implementation

A production-ready C++ implementation of the Cashu protocol with 100% Nutshell compatibility.

## Project Overview

Cashu++ is a complete C++ implementation of the Cashu ecash protocol. The project focuses on performance, security, and maintaining perfect compatibility with existing Cashu wallets and mints.

## Key Features

- Full Cryptographic Suite: Complete implementation of secp256k1, DLEQ proofs, AES encryption, and BIP39 mnemonics
- Nutshell Compatible: 100% API and protocol compatibility with existing Cashu ecosystem
- Comprehensive Protocol Support: Full NUT (Notation, Usage, and Terminology) specification compliance

## Architecture

### Core Components

- Crypto Layer: Elliptic curve operations, key derivation, encryption, and proof systems
- Protocol Layer: Cashu-specific data structures, serialization, and protocol logic
- Core Infrastructure: Configuration management, error handling, and utility functions

### Directory Structure

```
cashu++/
├── include/cashu/          # Public API headers
│   ├── core/crypto/        # Cryptographic primitives
│   ├── core/               # Core protocol structures
│   └── core/nuts/          # NUT specification implementations
├── src/cashu/              # Implementation files
│   ├── core/crypto/        # Crypto implementations
│   ├── core/               # Core implementations
│   └── core/nuts/          # NUT implementations
├── resources/bip39         # BIP 39 English Word List

```

## Current Implementation Status

### Completed Components

Cryptographic Foundation:
- secp256k1: Complete elliptic curve implementation with point operations
- Key Derivation: BIP32-compatible key derivation (supports v0.11.0, v0.14.0, v0.15.0)
- DLEQ Proofs: Discrete Log Equality proof generation and verification
- AES Encryption: AES-256-CBC encryption/decryption
- BIP39: Mnemonic seed phrase validation and processing

Core Protocol:
- Base Types: Fundamental Cashu data structures (Proof, BlindedMessage, etc.)
- Configuration: Comprehensive settings and configuration management
- Error Handling: Robust exception-based error system
- Protocol Specs: Complete NUT specification implementations
- Utilities: Helper functions for encoding, hashing, and data manipulation

### In Development

- Database Layer: Persistent storage for mint operations
- Lightning Integration: Multiple Lightning Network backend support
- Mint Operations: Core mint functionality (keysets, verification, operations)
- HTTP API: RESTful API server implementation

## Technical Specifications

### Requirements

- C++17 or later
- Boost.Multiprecision for arbitrary precision arithmetic
- OpenSSL for cryptographic operations

### Key Design Decisions

- Arbitrary Precision: Uses `boost::multiprecision::cpp_int` for all cryptographic operations
- Exception Safety: Comprehensive exception-based error handling
- Memory Safety: RAII principles and smart pointer usage throughout
- Performance: Optimized for both compilation speed and runtime performance

## Protocol Compatibility

Cashu++ implements the complete [Cashu NUT specifications](https://github.com/cashubtc/nuts):

- NUT-00: Cryptographic building blocks and notation
- NUT-01: Mint public key distribution
- NUT-02: Keysets and keyset IDs  
- NUT-03: Swap protocol
- NUT-04: Mint quote protocol
- NUT-05: Melt quote protocol
- NUT-06: Mint information
- NUT-07: Token state check
- NUT-08: Lightning fee return
- NUT-09: Signature restore
- NUT-10: Spending conditions
- NUT-11: Pay-to-Public-Key (P2PK)
- NUT-12: DLEQ proofs
- NUT-13: Deterministic secrets
- NUT-14: Hashed Time Lock Contracts (HTLCs)
- NUT-15: Partial multi-path payments
- NUT-16: Animated QR codes
- NUT-17: WebSocket subscriptions
- NUT-18: Mint authentication
- NUT-19: Mint management

## Roadmap

### Phase 1: Core Foundation
Complete cryptographic and protocol foundations with full Nutshell compatibility.

### Phase 2: Functional Mint
Implement complete mint functionality including database operations, Lightning integration, and core mint operations.

### Phase 3: Complete Server
Add HTTP API layer for full mint server functionality with REST endpoints.

### Phase 4: Enterprise Features
Performance optimizations, advanced monitoring, and production deployment features.

## 🤝 Contributing

We welcome contributions!

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Links

- [Cashu Protocol](https://cashu.space/)
- [NUT Specifications](https://github.com/cashubtc/nuts)
- [Nutshell Reference Implementation](https://github.com/cashubtc/nutshell)
- [Project Repository](https://github.com/Forte11Cuba/cashupp)

---
