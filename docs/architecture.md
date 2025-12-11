# Terminal-PGP Architecture

## System Components
```
┌─────────────────────────────────────────────────────────────┐
│                      CLIENT A                               │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐        │
│  │   Textual    │  │  PGP/GPG    │  │   Socket     │        │
│  │     UI       │←→│   Wrapper   │←→│   Client     │        │
│  └──────────────┘  └─────────────┘  └──────┬───────┘        │
└────────────────────────────────────────────┼────────────────┘
                                             │
                                   TLS/SSL   │
                                             │
                         ┌───────────────────▼────────────────┐
                         │         SERVER                     │
                         │  ┌──────────────────────────┐      │
                         │  │   Room Manager           │      │
                         │  │   (Broadcasts messages)  │      │
                         │  └──────────────────────────┘      │
                         └────────────┬───────────────────────┘
                                      │
                         ┌────────────┼────────────┐
                         │            │            │
                         ▼            ▼            ▼
                  ┌────────────┐ ┌────────────┐ ┌────────────┐
                  │ CLIENT B   │ │ CLIENT C   │ │ CLIENT N   │
                  └────────────┘ └────────────┘ └────────────┘
```

## Message Flow

1. **User A types message:** "Hello secure world"

2. **Client A encrypts:** For each recipient (B, C, N):
```python
encrypted_b = gpg.encrypt(message, recipient=B_public_key)
encrypted_c = gpg.encrypt(message, recipient=C_public_key)
encrypted_n = gpg.encrypt(message, recipient=N_public_key)
```

3. **Bundle creation:**
```json
{
  "sender": "alice@example.com",
  "ciphertexts": {
    "bob@example.com": "-----BEGIN PGP MESSAGE-----...",
    "charlie@example.com": "-----BEGIN PGP MESSAGE-----...",
    "nancy@example.com": "-----BEGIN PGP MESSAGE-----..."
  }
}
```

4. **Server broadcasts:** Sends bundle to all connected clients over TLS

5. **Each client attempts decryption:**
```python
decrypted = gpg.decrypt(ciphertexts[my_email], passphrase=my_passphrase)
if decrypted.ok:
    display_message(sender, decrypted.data)
```

## Security Properties

- **Confidentiality:** Only intended recipients can read messages
- **Authenticity:** PGP signatures prove sender identity
- **Transport Security:** TLS prevents eavesdropping on network
- **End-to-End Encryption:** Server cannot read message content
