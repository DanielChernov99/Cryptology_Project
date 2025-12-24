# Cryptology_Project

Secure data exchange system using GOST (CBC mode) for symmetric encryption, ECDH for key generation, and DSA for digital signatures. Implemented without high-level cryptographic libraries for academic purposes.

## Project Overview

This project implements a secure data exchange system designed to guarantee **confidentiality, integrity, and authenticity** of transmitted messages or files using a hybrid cryptographic approach.

The system combines symmetric encryption, public-key key exchange, and digital signatures, following academic constraints that prohibit the use of high-level cryptographic libraries.

## Cryptographic Components

### Symmetric Encryption
- GOST block cipher
- CBC (Cipher Block Chaining) mode
- Used to encrypt the transmitted data

### Key Generation and Exchange
- Elliptic Curve Diffie-Hellman (ECDH)
- Securely derives a shared secret key between communicating parties

### Digital Signatures
- Digital Signature Algorithm (DSA)
- Provides message authenticity and integrity verification

### Hash Functions
- Used only where permitted for integrity checks and digital signatures

## Security Properties
- **Confidentiality:** Ensured by GOST encryption in CBC mode
- **Integrity:** Ensured through cryptographic hashing and signature verification
- **Authenticity:** Ensured using DSA digital signatures

## Implementation Notes
- No use of high-level cryptographic libraries
- Cryptographic primitives are implemented manually
- Standalone system (no client–server architecture required)
- Focus on correctness, clarity, and academic evaluation

## Academic Context
This project was developed as part of a university cryptography course and demonstrates practical implementation of block cipher modes of operation, key exchange mechanisms, and digital signature schemes.
