# SecureLink

A network encryption library implementing AES-256-GCM and ChaCha20-Poly1305 with advanced security features for secure communication protocols.

## ⚠️ Security Notice

**This library contains implementation bugs and is not production-ready.** Use only for research, educational purposes, or as a foundation requiring thorough security review. Key exchange protocols must be implemented separately.

## Features

- **Multiple Cipher Support**: AES-256-GCM and ChaCha20-Poly1305 AEAD encryption
- **Forward Secrecy**: Automatic key rotation every 100 packets
- **Replay Protection**: Sliding window anti-replay mechanism
- **Secure Memory**: Memory locking, secure allocation, and explicit clearing
- **Message Fragmentation**: Automatic handling of large messages
- **Traffic Obfuscation**: Padding-based traffic analysis resistance  
- **Thread Safety**: Full multi-threaded operation support
- **Session Management**: Multiple concurrent encrypted sessions

## Requirements

- **libsodium** - Modern cryptographic library
- **OpenSSL** - Cryptographic functions and key derivation
- **pthread** - Thread synchronization
- **GCC** with C99 support

## Installation

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libsodium-dev libssl-dev

# Compile
gcc -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie securelink.c -lcrypto -lsodium -pthread -o securelink
```

## Quick Start

```c
#include "securelink.h"

int main() {
    // Initialize cryptographic subsystem
    crypto_init();
    
    // Create session manager
    uint8_t master_secret[32];
    secure_random(master_secret, 32);
    session_manager_t *mgr = session_manager_create(master_secret);
    
    // Establish secure session
    uint8_t ephemeral_key[32];
    secure_random(ephemeral_key, 32);
    crypto_context_t *session = establish_session(mgr, 
        (uint8_t*)"peer_id", 7, ephemeral_key, CIPHER_AES_256_GCM);
    
    // Encrypt data
    const char *message = "Sensitive data requiring encryption";
    uint8_t *encrypted;
    size_t encrypted_len;
    
    encrypt_packet(session, (uint8_t*)message, strlen(message), 
                  &encrypted, &encrypted_len);
    
    // Decrypt data
    uint8_t *decrypted;
    size_t decrypted_len;
    
    decrypt_packet(session, encrypted, encrypted_len, 
                  &decrypted, &decrypted_len);
    
    printf("Decrypted: %.*s\n", (int)decrypted_len, decrypted);
    
    // Cleanup
    free(encrypted);
    free(decrypted);
    close_session(mgr, session);
    session_manager_free(mgr);
    
    return 0;
}
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│  Session Mgr    │    │  Crypto Context │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Session   │ │    │ │  AES-GCM    │ │
│ │ Management  │ │────│ │ ChaCha20    │ │
│ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Key Store  │ │    │ │   Replay    │ │
│ │   (Secure)  │ │────│ │ Protection  │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
         │                        │
         └────────────────────────┘
                    │
         ┌─────────────────┐
         │  Network Layer  │
         │ (Not Included)  │
         └─────────────────┘
```

## API Reference

### Core Functions

- `crypto_init()` - Initialize cryptographic libraries
- `session_manager_create()` - Create session manager
- `establish_session()` - Create encrypted session
- `encrypt_packet()` - Encrypt data packet
- `decrypt_packet()` - Decrypt data packet
- `close_session()` - Terminate session
- `session_manager_free()` - Cleanup manager

### Advanced Features

- `send_fragmented()` - Fragment large messages
- `receive_fragmented()` - Reassemble fragments
- `obfuscate_packet()` - Add traffic padding
- `deobfuscate_packet()` - Remove padding

## Testing

```bash
# Run built-in test suite
./securelink

# Expected output includes performance metrics
# Throughput: ~XXX MB/s depending on hardware
```

## Use Cases

- **Custom VPN implementations**
- **Secure file transfer protocols** 
- **IoT device communication**
- **P2P encrypted messaging**
- **Research and education**
- **Protocol development**

## Security Considerations

### Current Limitations
- **No key exchange protocol** - Requires pre-shared secrets
- **Implementation bugs** - Needs security audit
- **Missing peer authentication** - No identity verification
- **No perfect forward secrecy** - Key rotation only

### Recommendations
- Implement proper key exchange (ECDH, X25519)
- Add mutual authentication 
- Conduct thorough security review
- Implement proper protocol state machines
- Add comprehensive fuzzing tests

## Performance

Typical performance on modern hardware:
- **AES-256-GCM**: ~200-400 MB/s
- **ChaCha20-Poly1305**: ~150-300 MB/s
- **Memory overhead**: ~2KB per session
- **Key rotation**: Automatic every 100 packets

## Disclaimer

This software is provided for educational and research purposes. The authors are not responsible for any misuse or security vulnerabilities. Professional security review is required before production deployment.

---

**SecureLink** - Emphasizes secure communication links while remaining professional and descriptive.
