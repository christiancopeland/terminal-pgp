# terminal-pgp

A secure, terminal-based chat application that uses PGP (Pretty Good Privacy) encryption for end-to-end encrypted communication. This application allows users to create secure chat rooms, generate PGP key pairs, and exchange encrypted messages with confidence.

## Tech Stack

- **Textual**: Terminal UI framework for creating the interactive interface
- **python-gnupg**: Python wrapper for GnuPG (GNU Privacy Guard)
- **Socket Programming**: For network communication between clients and servers
- **Threading**: For handling multiple connections simultaneously
- **JSON**: For structured data exchange between clients and server

## Security Considerations

### Threat Model

This application is designed for:
- **Protected:** Message content confidentiality using PGP encryption
- **Protected:** Message authenticity and integrity via PGP signatures
- **NOT Protected:** Metadata (who's talking to whom, message timing, room names)
- **NOT Protected:** Against endpoint compromise (if attacker has your passphrase)

### Known Limitations

- **No Perfect Forward Secrecy:** Compromised private key exposes all past messages
- **Metadata Leakage:** Server sees IP addresses, connection times, room names
- **Trust on First Use:** No key verification mechanism (vulnerable to MITM during key exchange)
- **Cleartext Passphrases in Memory:** Application holds passphrases in plaintext during session

### Security Roadmap

Planned improvements:
- [ ] Implement Double Ratchet algorithm (Signal Protocol) for forward secrecy
- [ ] Add key fingerprint verification UI
- [ ] Ephemeral message support (auto-delete after reading)
- [ ] Memory zeroization for sensitive data

## How It Works

### Architecture

terminal-pgp uses a client-server architecture:

1. **Server Component**: Handles room hosting, client connections, and message broadcasting
2. **Client Component**: Manages user connections to rooms and handles message encryption/decryption
3. **UI Component**: Terminal-based interface built with Textual

### Encryption Workflow

1. **Key Generation**: Users generate PGP key pairs (public/private keys)
2. **Authentication**: Users login with their email and passphrase
3. **Secure Communication**:
   - Messages are encrypted with the recipient's public key
   - Recipients decrypt messages using their private key and passphrase
   - The application supports pairwise encryption for group chats (separate encryption for each recipient)

### Message Flow

1. A user types a message in the chat interface
2. The message is encrypted with each recipient's public key, creating a bundle of ciphertexts
3. This bundle is sent to the server
4. The server broadcasts the bundle to all connected clients
5. Each client attempts to decrypt their specific ciphertext using their private key
6. Successfully decrypted messages are displayed in the chat UI

## Setup and Usage

### Prerequisites

- Python 3.7 or higher
- GnuPG installed on your system
- OpenSSL certificate for server
   - Only working for local testing for now
   - ```openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"```

### Installation

1. Clone the repository:
   ```
   git clone [repository-url]
   cd terminal-pgp
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Running the Application

The application requires multiple terminal instances to demonstrate the chat functionality:

#### Terminal 1 - First User
```bash
python app.py
```

1. Generate a key pair (Button: "Generate Key Pair")
   - Enter your email and a secure passphrase
   - Note the fingerprint displayed in the output

2. Login with your credentials (Button: "Login")
   - Enter the email and passphrase used in key generation

3. Host a chat room (Button: "Host Room")
   - Enter a room name
   - Specify a port number (e.g., 8000)

#### Terminal 2 - Second User
```bash
python app.py
```

1. Generate another key pair with different credentials
2. Login with the second set of credentials
3. Connect to the hosted room (Button: "Connect to Room")
   - Enter "127.0.0.1" as the Host IP
   - Enter the port number matching the hosted room

### Typical Usage Flow

1. Generate key pairs for all users
2. Login with user credentials
3. One user hosts a room
4. Other users connect to the room
5. Exchange encrypted messages
6. Close the chat when finished

## Core Features

- **Key Management**: Generate, list, update, and delete PGP key pairs
- **Secure Messaging**: End-to-end encrypted communication
- **Room Hosting**: Create private chat rooms
- **Group Chat**: Support for multiple users with pairwise encryption
- **Terminal UI**: Clean, intuitive interface for all operations

## Extending the Project

### Potential Improvements

1. **User Authentication Enhancement**
   - Implement a more robust authentication system
   - Add support for key verification and trust levels

2. **Persistent Storage**
   - Add message history with encrypted local storage
   - Support for exporting/importing encrypted conversation logs

3. **UI Enhancements**
   - File transfer capabilities
   - Emoji support
   - Markdown rendering for formatted messages

4. **Network Improvements**
   - Support for NAT traversal to enable connections across networks
   - Implement WebSocket support for web client compatibility
   - Add relay servers for improved connectivity

5. **Security Enhancements**
   - Perfect forward secrecy implementation
   - Key rotation mechanisms
   - Support for multiple encryption algorithms

6. **Usability Features**
   - Contact management system
   - Notifications for new messages
   - Status indicators (online, typing, etc.)

### Implementation Ideas

1. **Web Interface**
   ```python
   # Example of adding a Flask web interface
   from flask import Flask, render_template
   
   app = Flask(__name__)
   
   @app.route('/')
   def index():
       return render_template('chat.html')
   
   # Implement WebSocket for real-time communication
   ```

2. **Adding File Transfer**

To enhance the application with file transfer capabilities, you can extend the `PGPChatClient` class:

```python
# Add to PGPChatClient class
def send_file(self, filepath, recipient):
    with open(filepath, 'rb') as file:
        content = file.read()
        encrypted = encrypt_and_sign_message(
            self.app.user_email,
            self.app.user_passphrase,
            recipient,
            content
        )
        file_bundle = {
            "type": "file",
            "filename": os.path.basename(filepath),
            "sender": self.app.user_email,
            "content": encrypted
        }
        self.client_socket.sendall(json.dumps(file_bundle).encode("utf-8"))
```

3. **Message Persistence**

To add chat message persistence, you can extend the `PGPApp` class to encrypt and save chat logs locally:

```python
# Add to PGPApp class
def save_chat_history(self, room_name):
    chat_messages = [msg.text for msg in self.query_one(".chat-messages").children]
    encrypted = encrypt_and_sign_message(
        self.user_email,
        self.user_passphrase,
        self.user_email,  # Encrypt to self
        json.dumps(chat_messages).encode("utf-8")  # Ensure bytes are used
    )
    with open(f"{room_name}_history.gpg", "wb") as history_file:
        history_file.write(encrypted.data)
```

## Contribution

If you want to contribute to this project, consider implementing any of the suggested enhancements. Here's a step-by-step process for contributing:

1. **Fork the Repository**: Fork this project to your own GitHub account.
2. **Make Changes**: Implement new features or fix bugs in your fork.
3. **Create a PR**: Submit a pull request to the original repository with a descriptive title and comment explaining your changes.
4. **Review Process**: The PR will go through a review process before it is merged.

## Troubleshooting

- **Key Generation Errors**: Ensure GnuPG is installed correctly and verify that you have adequate permissions to write to the PGP key directory.
- **Connection Issues**: Check that both clients are connecting to the same host and port. Use `127.0.0.1` for local testing.
- **Decryption Failures**: Verify that recipients have their private keys loaded and the correct passphrase is being used.
- **Other Unmentioned Errors**: Application logs will be stored in a ```pgp_log``` file. Be sure to check it if you run into any errors, it will help in tracking down any caught exceptions

## Acknowledgments

- This project uses [python-gnupg](https://pypi.org/project/python-gnupg/) for PGP encryption and [Textual](https://textual.textualize.io/) for the terminal UI.

---

Feel free to reach out with questions or to discuss potential enhancements. Happy coding

