import gnupg
import getpass
import os
import logging
from io import StringIO, BytesIO
import socket 
import threading
import json

from textual.app import App, ComposeResult
from textual.widgets import Button, Header, Footer, Input, Label, TextArea
from textual.reactive import reactive
from textual.containers import Vertical, VerticalScroll, Horizontal

# Internal Imports
from encrypt_utils import generate_key_pair, decrypt_message, encrypt_and_sign_message

from client import PGPChatClient
from server import PGPChatServer

# Setup the logger
logging.basicConfig(
    filename="pgp_log",  # Log file name
    level=logging.DEBUG,  # Log all levels of events (DEBUG and above)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
)
logger = logging.getLogger(__name__)  # Create a logger instance



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
        self.user_email = None 
        self.user_passphrase = None

    def compose(self) -> ComposeResult:
        """Compose the app layout."""
        yield Header()
        yield Label("PGP Encryption Tool", id="title")
        yield Horizontal(  # Horizontal container for buttons
            Button("Login", id="login-menu"),
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
        yield Horizontal(
            VerticalScroll(id="chat-container", classes="chat-widget"),
            TextArea(id="output", text="")  
        )
        # yield VerticalScroll(id="chat-container", classes="chat-widget")
        # yield TextArea(id="output", text="")
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle mode selection and submission buttons."""
        logger.info(f"Button pressed: {event.button.id}")
        await self.case_match_buttons(event)

    def watch_mode(self, mode: str):
        """Update input fields dynamically when the mode is changed."""
        logger.info(f"Switched mode to: {mode}")
        self.check_modes(mode)

    def check_modes(self, mode: str):
        input_container = self.query_one("#input-container")
        input_container.remove_children()
        # chat_container = self.query_one("#chat-container")
        # chat_container.remove_children()
        if mode == "generate-key":
            input_container.mount(Input(placeholder="Enter Email", id="keygen-email"))
            input_container.mount(Input(placeholder="Enter Passphrase", password=True, id="keygen-pass"))
            input_container.mount(Button("Submit", id="submit-generate-key"))

        elif mode == "login":
            input_container.mount(Input(placeholder="Your Email (Key ID)", id="login-email"))
            input_container.mount(Input(placeholder="Passphrase", password=True, id="login-passphrase"))
            input_container.mount(Button("Login", id="login-btn"))

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
            chat_container.mount(Horizontal(send_btn, close_btn, classes="chat-buttons"))
            chat_container.refresh()

        input_container.refresh()
        # chat_container.refresh()
       

    async def case_match_buttons(self, event: Button.Pressed):
        match event.button.id:
            case "login-menu":
                self.mode = "login"
            case "login-btn":
                await self.handle_login()
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
                await self.handle_join_room()
                self.mode = "join-room"
            case "start-hosting":
                await self.handle_start_hosting()
            case "send-message-btn":
                message = self.query_one("#chat-input-field", Input).value
                await self.send_chat_message(message)
            case "close-chat-btn":
                chat_container = self.query_one("#chat-container")
                chat_container.remove_children()
                chat_container.refresh()
                self.mode = "output"
            case "list-keys":
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

    async def handle_login(self):
        email = self.query_one("#login-email", Input).value
        # TODO: Use byte arrays instead of strings for passwords in order to reliably clear them from memory after use. 
        passphrase = self.query_one("#login-passphrase", Input).value
        # Validate: Key exists?
        keys = gpg.list_keys(secret=True)
        key_emails = [uid for key in keys for uid in key['uids']]
        if not any(email in uid for uid in key_emails):
            self.query_one("#output", TextArea).text = "No private key for this email."
            logger.error(f"Login failed for {email}: key not found.")
            return
        self.user_email = email
        self.user_passphrase = passphrase
        self.mode = "output"
        self.query_one("#output", TextArea).text = f"Logged in as: {email}"
        logger.info(f"User logged in: {email}")
       

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
        self.query_one("#output", TextArea).text = "Fetching keys..."
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

        if not new_passphrase: 
            raise ValueError("Passphrase must be provided when generating keys, homie.")

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

    async def handle_start_hosting(self):
        room_name = self.query_one("#room-name", Input).value
        port_number = int(self.query_one("#port-number", Input).value)
        # Run server in background thread
        logger.info(f"Starting room {room_name}")
        self.server = PGPChatServer("127.0.0.1", port_number, app=self)
        logger.info(f"Server Instantiated:\n{self.server}\n")
        try:
            server_thread = threading.Thread(
                target=self.server.start_server_in_thread, 
                daemon=True)
            server_thread.start()
        except Exception as e:
            logger.error(f"Failed to start server thread: {e}")

        if self.server.ready_event.wait(timeout=10.0):
            try:
                self.chat_client = PGPChatClient("127.0.0.1", port_number, app=self)
                client_thread = threading.Thread(
                    target=self.chat_client.connect_to_server, 
                    daemon=True)
                client_thread.start()
                # NEED TO SETUP SERVER SYNC TO ACQUIRE USER LOGIN INFO, MUST BE ENCRYPTED
                self.set_room_members([self.user_email, ""])
            except Exception as e:
                logger.error(f"Failed to connect to server in handle_start_hosting(): {e}")
        else:
            logger.error("Timed out waiting for server to start.")

        self.mode = "start-hosting"

    async def handle_join_room(self):
        host_ip = self.query_one("#host-ip", Input).value
        port_number = int(self.query_one("#port-number-connect", Input).value)
        # Establish client connection in separate thread
        logger.info(f"Starting client thread. Connecting to {host_ip}:{port_number}")
        self.chat_client = PGPChatClient(host_ip, port_number, app=self)
        client_thread = threading.Thread(target=self.chat_client.connect_to_server)
        client_thread.start()

    async def send_chat_message(self, message):
        """Send the chat message from the input field over the socket."""
        if not message.strip():
            return  # Don't send empty messages
        # Display your own message in the chat UI
        chat_container = self.query_one("#chat-container")
        chat_area = chat_container.query_one(Vertical)
        chat_area.mount(Label(f"You: {message}"))
        self.app.query_one("#chat-input-field", Input).value = ""

        # Send over the socket if connected
        if (
            self.chat_client
            and hasattr(self.chat_client, "client_socket")
            and self.chat_client.client_socket
        ):
            try:
                # --- PAIRWISE ENCRYPTION BUNDLE SEND --- 
                room_members = getattr(self.chat_client, "room_members", None)
                if not self.chat_client or not getattr(self.chat_client, "room_members", None):
                    self.query_one("#output", TextArea).text = "Room members not set yet. Please wait for the roster update before sending."
                    logger.error("Attempt to send chat message before room_members set.")
                    return
                if not self.chat_client.room_members:
                    self.query_one("#output", TextArea).text = "No one in room yet."
                    logger.error("No members in room to send to.")
                    return
                
                # Add own email if not present so self-encryption works
                if self.user_email not in room_members:
                    room_members.append(self.user_email)

                logger.debug(f"send_chat_message() room members: {room_members}")
                
                ciphertexts = {}
                for recipient_email in room_members:
                    recipient_fp = self.chat_client.get_fingerprint_for_email(recipient_email)
                    if not recipient_fp:
                        logger.error(f"Missing PGP fingerprint for {recipient_email} - skipping.")
                        continue
                    encrypted = encrypt_and_sign_message(
                    self.user_email, 
                    self.user_passphrase, 
                    recipient_fp, 
                    message
                    )
                    ciphertexts[recipient_email] = encrypted

                bundle = {
                        "sender": self.user_email,
                        "ciphertexts": ciphertexts
                    }
                bundle_str = json.dumps(bundle)
                self.chat_client.client_socket.sendall(bundle_str.encode("utf-8"))
                logger.info(f"Sent bundle to server for broadcast:\n{bundle_str.encode('utf-8')}\n")
                    # --- PAIRWISE ENCRYPTION SEND ---
                # OPTIONAL: encrypt here if desired

                    ## REWORK ENCRYPT_AND_SIGN_MESSAGE SIGNATURE TO LOOKUP KEYS INSTEAD OF BEING PROVIDED THEM
                    ## KEYS WILL BE SUBMITTED TO ROOM SERVER IN MEMORY AND NOT STORED PERSISTENTLY AFTER SHUTDOWN
                


                # self.chat_client.client_socket.sendall(message.encode("utf-8"))
                # self.chat_client.send_encrypted_message(message)
                # self.chat_client.send_messages(self.chat_client.client_socket)
            except Exception as e:
                logger.error(f"Failed to send message: {e}")
            # Optionally, notify the user in the UI
        else:
            logger.error("No active client socket; cannot send message.")

    def set_room_members(self, members):
        if self.chat_client:
            self.chat_client.room_members = members
            self.chat_client.email_to_fp = {}
            for key in gpg.list_keys():
                for uid in key["uids"]:
                    for email in members:
                        if email in uid:
                            self.chat_client.email_to_fp[email] = key["fingerprint"]


if __name__ == '__main__':

    # Setup directory for keys
    os.makedirs('./pgp_keys', exist_ok=True)
    gpg = gnupg.GPG(gnupghome='./pgp_keys')


    app = PGPApp()
    app.run()
