# **PGP Encryption Tool with Hydroxide Integration**

## **Overview**
This project is a terminal-based **PGP encryption tool** built using Python with the [Textual](https://github.com/Textualize/textual) framework. It uses GPG (GnuPG) for PGP encryption, decryption, key management, and securely encrypting and decrypting messages. We've integrated **Hydroxide** to enable seamless sending of encrypted emails through **ProtonMail** without requiring ProtonMail's paid Bridge software.

The application provides a user-friendly interface for generating PGP key pairs, managing keys, encrypting/decrypting text, and sending encrypted emails using ProtonMail or your local SMTP server. Hydroxide facilitates local proxying for ProtonMail's encryption, ensuring privacy and security.

---

## **Features**
NOTE: Email functionality is not fully implemented yet. This is only useful for managing keys, and encrypting/decrypting messages currently
1. **PGP Key Management**:
   - Generate PGP key pairs with email addresses and passphrases.
   - List all public keys and their fingerprints.
   - Delete and update existing keys.
   - Update private key passphrases.

2. **Message Encryption and Decryption**:
   - Encrypt plaintext messages using a recipient's public key.
   - Sign messages with the sender's private key for authenticity.
   - Decrypt encrypted messages using the sender’s private key and passphrase.

3. **Send Secure Emails**:
   - Send encrypted emails via:
     - **Hydroxide** for free ProtonMail integration.
     - Custom SMTP servers (e.g., Gmail, SendGrid, or personal SMTP servers).
   - Encrypt email bodies before sending.
   - Support for email attachments (future enhancement).

4. **Hydroxide Integration**:
   - Acts as a free open-source ProtonMail Bridge replacement.
   - Enables local SMTP/IMAP for ProtonMail accounts for both sending and receiving encrypted messages.

5. **Logging**:
   - Logs all operations (e.g., key generation, encryption, decryption, email sending) to a file for debugging.

---

## **Setup Instructions**

### **Prerequisites**
1. Python 3.9+ installed on your machine.
2. GnuPG installed:
   - For Ubuntu/Debian:
     ```bash
     sudo apt update
     sudo apt install gnupg
     ```
   - For macOS:
     ```bash
     brew install gpg
     ```
3. Hydroxide installed for ProtonMail integration (if needed):
   - Install with `Go`:
     ```bash
     git clone https://github.com/emersion/hydroxide.git
     cd hydroxide
     go build ./cmd/hydroxide
     ```
   - Authenticate and start Hydroxide:
     ```bash
     ./hydroxide auth 
     ./hydroxide serve
     ```

---

### **Installation**
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/pgp-encryption-tool.git
   cd pgp-encryption-tool
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure `styles.css` is in the same directory for styling.

---

### **Usage**

1. **Run the Application**:
   ```bash
   python app.py
   ```
   The application opens in a terminal interface powered by Textual.

2. **Features Overview**:
   - **Generate Key Pair**:
     - Enter your email and passphrase to create a PGP key pair.
     - The key is saved in the `.pgp_keys` directory.
   - **List Keys**:
     - Displays all public keys and fingerprints in the keyring.
   - **Encrypt Message**:
     - Provide the sender's email, passphrase, recipient's email, and plaintext message.
     - The tool encrypts and optionally signs the message.
   - **Decrypt Message**:
     - Enter the encrypted message and the private key’s passphrase to reveal the plaintext.
   - **Update/Delete Keys**:
     - Modify or remove keys using fingerprints.

3. **Sending Emails**:
   - Relay emails through **Hydroxide** or a custom SMTP server:
     - **Hydroxide**:
       Ensure Hydroxide is running:
       ```bash
       ./hydroxide serve
       ```
       Set SMTP as:
       ```plaintext
       Host: 127.0.0.1
       Port: 1025
       ```
     - **Custom SMTP Server**:
       Provide the SMTP host, port, username, and password in the app.

---

## **Hydroxide Setup for ProtonMail**
Hydroxide is an open-source tool that acts as a free replacement for ProtonMail Bridge. It provides local IMAP/SMTP access to ProtonMail. Here's a more in-depth guide:

1. **Install and Build Hydroxide**:
   ```bash
   git clone https://github.com/emersion/hydroxide.git
   cd hydroxide
   go build ./cmd/hydroxide
   ```
2. **Authenticate ProtonMail**:
   Run the following command and log in with your ProtonMail credentials:
   ```bash
   ./hydroxide auth 
   ```
3. **Run Hydroxide in Background**:
   Start Hydroxide in server mode:
   ```bash
   ./hydroxide serve
   ```
   This sets up:
   - **SMTP**: `127.0.0.1:1025`
   - **IMAP**: `127.0.0.1:1143`

4. **Using Hydroxide in the Script**:
   Update the app’s SMTP configuration to:
   ```plaintext
   SMTP Host: 127.0.0.1
   SMTP Port: 1025
   Username: 
   Password: 
   ```

Example email-sending function:
```python
with smtplib.SMTP("127.0.0.1", 1025) as server:
    server.login(sender_email, "hydroxide_generated_password")
    server.send_message(msg)
```

---

## **Example Scenarios**
Here are common use cases for the tool:

### **1. Secure Message Encryption**
Use PGP to encrypt a plaintext message:
1. Generate a key pair for yourself and import the recipient’s public key.
2. Encrypt the message and send it to the recipient securely.
3. The recipient decrypts the message using their private key.

### **2. Send ProtonMail-Encrypted Emails**
With Hydroxide running:
1. Compose an email in the app.
2. Relay emails through Hydroxide’s local SMTP.
3. Email is encrypted client-side before being sent through ProtonMail.

### **3. Key Lifecycle Management**
- Periodically update private key passphrases.
- Rotate keys by creating new ones and securely exporting/importing them.

---
