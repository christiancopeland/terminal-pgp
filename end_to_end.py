import gnupg
import getpass
import os
import logging
from io import StringIO
import socket 
import threading

from textual.app import App, ComposeResult
from textual.widgets import Button, Header, Footer, Input, Label, TextArea
from textual.reactive import reactive
from textual.containers import Vertical, VerticalScroll, Horizontal

# Internal Imports
from encrypt_utils import generate_key_pair, decrypt_message, encrypt_and_sign_message


# Setup the logger
logging.basicConfig(
    filename="pgp_log",  # Log file name
    level=logging.DEBUG,  # Log all levels of events (DEBUG and above)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
)
logger = logging.getLogger(__name__)  # Create a logger instance

class PGPChatServer:
    def __init__(self, host: str, port: int, app=None):
        self.host = host 
        self.port = port 
        self.server_socket = None 
        self.clients = []
        self.room_names = []
        self.app = app
        logger.debug(f"PGPChatServer initialized on host {self.host} and port {self.port}")

    def start_server(self):
        logger.info("Attempting to start the PGP chat server.")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            logger.info(f"Server is listening on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to bind/listen on {self.host}:{self.port}: {e}")
            return

        while True:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"Accepted connection from {address}")
                self.clients.append(client_socket)
                logger.info(f"Current clients: {[c.getpeername() for c in self.clients if c]}")

                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_handler.start()
                logger.debug(f"Client handler thread started for {address}")
            except Exception as e:
                logger.error(f"Error in start_server():\n{e}\n")
    
    def start_server_in_thread(room_name, port_number):
        try:
            server = PGPChatServer("192.168.1.218", port_number)
            logger.info(f"Hosting room {room_name} on port {port_number}.")
            server.start_server()
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            logger.error(f"Error in start_server_in_thread():\n{e}\n")
            exit(0)

    def connect_to_server(self):
        logger.info(f"Connecting to server at {self.host}:{self.port}")
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            logger.info("Successfully connected to server.")

            receiver_thread = threading.Thread(target=self.receive_messages, args=(client_socket,))
            receiver_thread.start()
            logger.debug("Receiver thread started.")

            sender_thread = threading.Thread(target=self.send_messages, args=(client_socket,))
            sender_thread.start()
            logger.debug("Sender thread started.")
        except Exception as e:
            logger.error(f"Error in connect_to_server():\n{e}\n")

    # NEED TO INTEGRATE INPUTS WITH TEXTUAL UI
    def send_messages(self, client_socket):
        logger.info("Sender thread running. Ready to send messages.")
        while True:
            try:
                message = self.query_one("#chat-input-field", Input).value
                #Encrypt before sending
                logger.debug(f"Encrypting outgoing message: {message}")
                encrypted_mesage = encrypt_and_sign_message(sender_email, passphrase, recipient_email, message)
                client_socket.sendall(encrypted_message)
                logger.info("Sent encrypted message to server.")
                self.query_one("#chat-input-field", Input).value = ""
            except Exception as e:
                logger.error(f"Error in send_messages()\n{e}\n")
                break
    
    def receive_messages(self, client_socket):
        logger.info("Receiver thread running. Ready to receive messages.")
        while True:
            try:
                message = client_socket.recv(1024)
                logger.debug(f"Received raw message: {message}")
                if not message:
                    logger.info("No message received. Closing receiver thread.")
                    break

                def update_ui():
                    try:
                        chat_container = self.app.query_one("#chat-container")
                        chat_area = self.query_one("#chat-container").query_one(Vertical)
                        chat_area.mount(Label("Received: " + str(message)))
                        logger.info(f"Displayed incoming message: {message}")
                    except Exception as e:
                        logger.error(f"Error updating UI from receive_messages():\n{e}\n")

                # This seems way off kilter. Seems un-sane. Look for better way of conditionally updating UI, if conditional updating is even necessary
                if self.app:
                    self.app.call_from_thread(update_ui)
                else:
                    logger.warning("No app reference in PGPChatServer; cannot update UI.")        
            except Exception as e:
                logger.error(f"Error in send_messages():\n{e}\n")
                break
        
    def handle_client(self, client_socket):
        address = None
        try:
            address = client_socket.getpeername()
            logger.info(f"Started handler for client {address}")
        except Exception:
            logger.warning("Could not retrieve client address.")
        while True:
            try:
                message = client_socket.recv(1024)
                logger.debug(f"Received message from client {address}: {message}")
                if not message:
                    logger.info(f"Client {address} disconnected. Removing client.")
                    self.remove_client(client_socket)
                    break
                logger.info(f"Broadcasting message from {address} to other clients.")
                self.broadcast(message, client_socket)
            except Exception as e:
                logger.error(f"Error in handle_client(): \n{e}\n")
                break

    def broadcast(self, message, sender_socket):
        logger.info(f"Broadcasting message to {len(self.clients) - 1} clients (excluding sender).")
        for client_socket in self.clients:
            if client_socket != sender_socket:
                try:
                    client_socket.sendall(message)
                    logger.debug(f"Sent broadcast message to {client_socket.getpeername()}")
                except Exception as e:
                    logger.error(f"Failed to send message to {client_socket.getpeername()}: {e}")

    def remove_client(self, client_socket):
        try:
            address =  client_socket.getpeername()
        except Exception:
            address = "<unknown>"
        try:
            self.clients.remove(client_socket)
            client_socket.close()
            logger.info(f"Removed and closed connection for client {address}. Remaining clients: {len(self.clients)}")
        except Exception as e:
            logger.error(f"Error removing client {address}: {e}")



class PGPApp(App):
    """A Textual-based terminal front end for your PGP project."""
    CSS_PATH = "./styles.css"
    # Reactive attributes for tracking mode
    mode = reactive("output")
    chat_active = reactive(False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chat_client = None
        self.server = None

    def compose(self) -> ComposeResult:
        """Compose the app layout."""
        yield Header()
        yield Label("PGP Encryption Tool", id="title")
        yield Horizontal(  # Horizontal container for buttons
            Button("Generate Key Pair", id="generate-key"),
            Button("List Keys", id="list-keys"),
            Button("Update Key", id="update-key"),
            Button("Delete Key", id="delete-key"),
            Button("Encrypt Message", id="encrypt"),
            Button("Decrypt Message", id="decrypt"),
            Button("Host Room", id="host-room"),
            Button("Connect to Room", id="connect-room"),
            id="buttons-container",
            classes="buttons-row",  # Add CSS class for styling
        )
        yield VerticalScroll(id="input-container")  # Dynamic container for inputs
        yield VerticalScroll(id="chat-container", classes="chat-widget")
        yield TextArea(id="output", text="")
        yield Footer()

    def watch_mode(self, mode: str):
        """Update input fields dynamically when the mode is changed."""
        logger.info(f"Switched mode to: {mode}")
        self.check_modes(mode)

    def check_modes(self, mode: str):
        input_container = self.query_one("#input-container")
        input_container.remove_children()
        chat_container = self.query_one("#chat-container")
        chat_container.remove_children()
        if mode == "generate-key":
            input_container.mount(Input(placeholder="Enter Email", id="keygen-email"))
            input_container.mount(Input(placeholder="Enter Passphrase", password=True, id="keygen-pass"))
            input_container.mount(Button("Submit", id="submit-generate-key"))
        elif mode == "encrypt":
            input_container.mount(Input(placeholder="Enter Sender Email", id="encrypt-sender"))
            input_container.mount(Input(placeholder="Enter Sender Passphrase", password=True, id="encrypt-pass"))
            input_container.mount(Input(placeholder="Enter Recipient Email", id="encrypt-recipient"))
            input_container.mount(Input(placeholder="Enter Message to Encrypt", id="encrypt-message"))
            input_container.mount(Button("Submit", id="submit-encrypt"))
        elif mode == "decrypt":
            input_container.mount(TextArea(text="<DELETE THIS. Enter Encrypted Message>", id="decrypt-message",))
            input_container.mount(Input(placeholder="Enter Decryption Passphrase of Recipient", password=True, id="decrypt-pass"))
            input_container.mount(Button("Submit", id="submit-decrypt"))
        elif mode == "delete-key":
            input_container.mount(Input(placeholder="Enter Fingerprint to Delete", id="delete-fingerprint"))
            input_container.mount(Input(placeholder="Enter Passphrase", password=True, id="delete-passphrase"))
            input_container.mount(Button("Submit", id="submit-delete-key"))
        elif mode == "update-key":
            input_container.mount(Input(placeholder="Enter Fingerprint to Update", id="update-fingerprint"))
            input_container.mount(Input(placeholder="Enter Current Passphrase", password=True, id="update-current-passphrase"))
            input_container.mount(Input(placeholder="Enter New Passphrase", password=True, id="update-passphrase"))
            input_container.mount(Button("Submit", id="submit-update-key"))
        elif mode == "host-room":
            input_container = self.query_one("#input-container")
            input_container.remove_children()
            input_container.mount(Input(placeholder="Room Name", id="room-name"))
            input_container.mount(Input(placeholder="Port Number", id="port-number"))
            input_container.mount(Button("Start Hosting", id="start-hosting"))
        elif mode == "connect-room":
            input_container = self.query_one("#input-container")
            input_container.remove_children()
            input_container.mount(Input(placeholder="Host IP", id="host-ip"))
            input_container.mount(Input(placeholder="Port Number", id="port-number-connect"))
            input_container.mount(Button("Join Room", id="join-room"))
        elif mode == "start-hosting" or mode == "join-room":
            # Show chat UI
            chat_container = self.query_one("#chat-container")
            chat_container.remove_children()
            chat_container.mount(Label("Chat Area"))

            chat_area = Vertical(classes="chat-messages")
            chat_container.mount(chat_area)

            input_field = Input(classes="chat-input", id="chat-input-field", placeholder="Type your message here")
            chat_container.mount(input_field)

            send_btn = Button("Send", id="send-message-btn", classes="send-btn")
            close_btn = Button("Close Chat", id="close-chat-btn", classes="close-chat-btn")
            chat_container.mount(Horizontal(send_btn, close_btn))

        input_container.refresh()
        chat_container.refresh()
       

    async def case_match_buttons(self, event: Button.Pressed):
        match event.button.id:
            case "generate-key":
                self.mode = "generate-key"
            case "encrypt":
                self.mode = "encrypt"
            case "decrypt":
                self.mode = "decrypt"
            case "delete-key":
                self.mode = "delete-key"
            case "update-key":
                self.mode = "update-key"
            case "host-room":
                self.mode = "host-room"
            case "connect-room":
                self.mode = "connect-room"
            case "join-room":
                host_ip = self.query_one("#host-ip", Input).value
                port_number = int(self.query_one("#port-number-connect", Input).value)
                # Establish client connection in separate thread
                logger.info(f"Starting client thread. Connecting to {host_ip}:{port_number}")
                self.chat_client = PGPChatServer(host_ip, port_number, app=self)
                client_thread = threading.Thread(target=self.chat_client.connect_to_server, args=(host_ip, port_number))
                client_thread.start()
                self.mode = "join-room"
            case "start-hosting":
                room_name = self.query_one("#room-name", Input).value
                port_number = int(self.query_one("#port-number", Input).value)
                # Run server in background thread
                logger.info(f"Starting room {room_name}")
                self.server = PGPChatServer("192.168.1.218", port_number, app=self)
                server_thread = threading.Thread(target=self.server.start_server_in_thread, args=(room_name, port_number))
                server_thread.daemon = True
                server_thread.start()
                self.mode = "start-hosting"
            case "send-message-btn":
                message = self.query_one("#chat-input-field", Input).value
                # This is where we encrypt and send using P2P logic
                chat_container = self.query_one("#chat-container")
                chat_area = chat_container.query_one(Vertical)
                chat_area.mount(Label(message))
                self.query_one("#chat-input-field", Input).value = ""
            case "close-chat-btn":
                chat_container = self.query_one("#chat-container")
                chat_container.remove_children()
                self.mode = "output"
            case "list-keys":
                self.query_one("#output", TextArea).text = "Fetching keys..."
                await self.handle_list_keys()
            case "submit-generate-key":
                await self.handle_generate_key()
            case "submit-encrypt":
                await self.handle_encrypt()
            case "submit-decrypt":
                await self.handle_decrypt()
            case "submit-delete-key":
                await self.handle_delete_key()
            case "submit-update-key":
                await self.handle_update_key()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle mode selection and submission buttons."""
        logger.info(f"Button pressed: {event.button.id}")
        await self.case_match_buttons(event)
        

    async def handle_generate_key(self):
        """Generate a key pair."""
        email = self.query_one("#keygen-email", Input).value
        passphrase = self.query_one("#keygen-pass", Input).value
        logger.info(f"Generating key pair: email={email}")
        try:
            key = generate_key_pair(email, passphrase)
            self.query_one("#output", TextArea).text = f"Key Generated! Fingerprint: {key.fingerprint}"
        except Exception as e:
            logger.error(f"Error generating key pair: {e}")
            self.query_one("#output", TextArea).text = f"Error: {e}"

    async def handle_list_keys(self):
        """List keys in the keyring."""
        logger.info("Fetching generated keys...")
        try:
            keys = gpg.list_keys()  # Fetch the list of public keys
            if keys:
                key_list = "\n".join(
                    [f"Email: {key['uids'][0]}, Fingerprint: {key['fingerprint']}" for key in keys]
                )
                logger.info(f"Keys listed successfully:\n{key_list}")
                self.query_one("#output", TextArea).text = f"Available Keys:\n{key_list}"
            else:
                logger.info("No keys found in the keyring.")
                self.query_one("#output", TextArea).text = "No keys found."
        except Exception as e:
            logger.error(f"Error listing keys: {e}")
            self.query_one("#output", TextArea).text = f"Error: {e}"

    async def handle_delete_key(self):
        """Delete a key based on its fingerprint."""
        fingerprint = self.query_one("#delete-fingerprint", Input).value
        passphrase = self.query_one("#delete-passphrase", Input).value
        logger.info(f"Deleting key: {fingerprint}")
        try:
            # Delete the secret (private) key
            secret_result = gpg.delete_keys(fingerprint, secret=True, passphrase=passphrase)
            
            if not secret_result:
                raise Exception(f"Failed to delete the secret key with fingerprint: {fingerprint}")
            logger.info(f"Secret key deleted for fingerprint: {fingerprint}")

            # Delete the public key
            public_result = gpg.delete_keys(fingerprint, secret=False, passphrase=passphrase)
            
            if not public_result:
                raise Exception(f"Failed to delete the public key with fingerprint: {fingerprint}")
            logger.info(f"Public key deleted for fingerprint: {fingerprint}")
            
            self.query_one("#output", TextArea).text = f"Key deleted successfully: {fingerprint}"

        except Exception as e:
            logger.error(f"Error deleting key: {e}")
            self.query_one("#output", TextArea).text = f"Error: {e}"


    async def handle_update_key(self):
        """Update the passphrase for a key."""
        fingerprint = self.query_one("#update-fingerprint", Input).value
        current_passphrase = self.query_one("#update-current-passphrase", Input).value
        new_passphrase = self.query_one("#update-passphrase", Input).value
        logger.info(f"Updating key passphrase for fingerprint: {fingerprint}")

        try:
            # Enable loopback for pinentry
            gpg.options = ["--pinentry-mode", "loopback"]
            # Sequence of commands for interactive --edit-key
            commands = [
                "passwd",  # Enter passphrase change mode
                current_passphrase,  # Provide the current passphrase
                new_passphrase,  # Enter the new passphrase
                new_passphrase,  # Confirm the new passphrase
                "save",  # Save the changes
            ]
            # Join commands with newlines for interactive input simulation
            command_input = StringIO("\n".join(commands) + "\n")
            results = any
            # Call GPG's handle_io to execute the command sequence
            result = gpg._handle_io(["--command-fd", "0", "--status-fd", "2", "--edit-key", fingerprint],
                StringIO(u'\n'.join(commands)), results
            )
            # Check the result for success
            if "gpg: success" in result.stderr:
                logger.info(f"Passphrase updated successfully for key: {fingerprint}")
                self.query_one("#output", TextArea).text = f"Passphrase updated successfully for key: {fingerprint}"
            else:
                raise Exception("Failed to update the passphrase. Please check the logs for details.")
        except Exception as e:
            logger.error(f"Error updating key passphrase: {e}")
            self.query_one("#output", TextArea).text = f"Error: {e}"

    async def handle_encrypt(self):
        """Encrypt a message."""
        sender = self.query_one("#encrypt-sender", Input).value
        passphrase = self.query_one("#encrypt-pass", Input).value
        recipient = self.query_one("#encrypt-recipient", Input).value
        message = self.query_one("#encrypt-message", Input).value
        logger.info(f"Encrypting message from {sender} to {recipient}")
        try:
            encrypted = encrypt_and_sign_message(sender, passphrase, recipient, message)
            logger.info(f"Encrypted: \n{encrypted}\n")
            self.query_one("#output", TextArea).text = f"Encrypted Message:\n{encrypted}"
        except Exception as e:
            logger.error(f"Failed to encrypt message from {sender} to {recipient}")
            self.query_one("#output", TextArea).text = f"Error: {e}"

    async def handle_decrypt(self):
        """Decrypt a message."""
        encrypted_message = self.query_one("#decrypt-message", TextArea).text
        passphrase = self.query_one("#decrypt-pass", Input).value
        logger.info(f"Decrypting message")
        try:
            decrypted = decrypt_message(encrypted_message, passphrase)
            self.query_one("#output", TextArea).text = f"Decrypted Message:\n{decrypted}"
        except Exception as e:
            logger.error(f"Error decrypting message")
            self.query_one("#output", TextArea).text = f"Error: {e}"

# WORK IN PROGRESS, DEFINITELY DOES NOT WORK RIGHT NOW
    async def handle_send_protonmail(self):
        """Send an encrypted email via ProtonMail."""
        sender_email = self.query_one("#sender-email", Input).value
        sender_passphrase = self.query_one("#sender-passphrase", Input).value
        recipient_email = self.query_one("#recipient-email", Input).value
        message_body = self.query_one("#email-body", TextArea).text
        subject = self.query_one("#email-subject", Input).value
        smtp_server = "smtp.protonmail.com"  # ProtonMail SMTP server
        smtp_port = 465  # For SSL/TLS communication

        logger.info(f"Encrypting and sending an email from {sender_email} to {recipient_email}")

        try:
            # Encrypt the message using the recipient's public key
            encrypted_data = gpg.encrypt(
                message_body, recipient_email, sign=sender_email, passphrase=sender_passphrase
            )
            if not encrypted_data.ok:
                raise Exception(f"Encryption failed: {encrypted_data.status}")

            # Create the email
            msg = EmailMessage()
            msg["From"] = sender_email
            msg["To"] = recipient_email
            msg["Subject"] = subject
            msg.set_content(str(encrypted_data))  # Encrypted message as content

            # Send the email via ProtonMail SMTP
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                server.login(sender_email, sender_passphrase)
                server.send_message(msg)

            logger.info(f"Encrypted email sent successfully to {recipient_email}")
            self.query_one("#output", TextArea).text = f"Encrypted email sent successfully to {recipient_email}"

        except Exception as e:
            logger.error(f"Error sending encrypted email: {e}")
            self.query_one("#output", TextArea).text = f"Error: {e}"



if __name__ == '__main__':

    # Setup directory for keys
    os.makedirs('./pgp_keys', exist_ok=True)
    gpg = gnupg.GPG(gnupghome='./pgp_keys')


    app = PGPApp()
    app.run()
