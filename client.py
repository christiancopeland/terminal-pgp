import threading 
import socket
import logging
import json
import gnupg
import ssl

from textual.containers import Vertical
from textual.widgets import Input, Label

from encrypt_utils import encrypt_and_sign_message, decrypt_message


# Setup the logger
logging.basicConfig(
    filename="pgp_log",  # Log file name
    level=logging.DEBUG,  # Log all levels of events (DEBUG and above)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
)
logger = logging.getLogger(__name__)  # Create a logger instance

class PGPChatClient:
    def __init__(self, host, port, app=None):
        self.host = host
        self.port = port 
        self.app = app 
        self.client_socket = None
        self.room_members = None
        self.gpg = gnupg.GPG(gnupghome="./pgp_keys")

    def set_room_members(self, members):
        self.room_members = members
        self.email_to_fp = {}
        for key in self.gpg.list_keys():
            for uid in key['uids']:
                for email in members:
                    if email in uid:
                        self.email_to_fp[email] = key['fingerprint']
    
    def get_fingerprint_for_email(self, email):
        if hasattr(self, "email_to_fp"):
            return self.email_to_fp.get(email)
        return None


    def connect_to_server(self):
        logger.info(f"Connecting to server at {self.host}:{self.port}")
        try:
            ## Attempting to implement secure sockets with TLS Certificates
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('ECDHE+AESGCM')
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            secure_socket = context.wrap_socket(self.client_socket, server_hostname=self.host)
            secure_socket.connect((self.host, self.port))
            self.client_socket = secure_socket
            logger.info("Successfully connected to server.")
            server_email = "server@chat.local"
            if self.app and hasattr(self.app, "user_email"):
                identity_info = json.dumps({
                    "type": "identity", 
                    "email": self.app.user_email})
                encrypted_identity = self.gpg.encrypt(
                    identity_info, server_email
                )
                if not encrypted_identity.ok:
                    logger.error(f"Failed to encrypt identity for server: {encrypted_identity.status}")
                    exit(0)
                else:
                    self.client_socket.sendall(identity_info.encode("utf-8"))
                    logger.info(f"Sent encrypted identity info to server: {self.app.user_email}")
            else:
                logger.warning("No self.app.user_email found -- not sending identity.")
            receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receiver_thread.start()
            logger.debug("Receiver thread started.")
        except Exception as e:
            logger.error(f"Error in connect_to_server():\n{e}\n")
    

    def send_messages(self, client_socket):
        logger.info("Sender thread running. Ready to send messages.")
        if not self.client_socket:
            logger.error("No client socket available for sending.")
            return
        while True:
            try:
                message = self.app.query_one("#chat-input-field", Input).value
                #Encrypt before sending
                logger.debug(f"Encrypting outgoing message: {message}")
                encrypted_mesage = encrypt_and_sign_message(sender_email, passphrase, recipient_email, message)
                client_socket.sendall(encrypted_message)
                logger.info("Sent encrypted message to server.")
                self.app.query_one("#chat-input-field", Input).value = ""
            except Exception as e:
                logger.error(f"Error in send_messages()\n{e}\n")
                break


    def receive_messages(self):
        logger.info("Receiver thread running. Ready to receive messages.")
        while True:
            try:
                message = self.client_socket.recv(4096).decode("utf-8")
                logger.debug(f"Received raw message: {message}")
                if not message:
                    logger.info("No message received. Closing receiver thread.")
                    break

                display_message = ""
                bundle = None

                # 1. Try to parse as JSON
                try:
                    bundle = json.loads(message)
                    logger.debug(f"JSON Loaded from message: {bundle}")
                except Exception as e:
                    # If not JSON, it could be a PGP envelope (encrypted roster, identity, etc)
                    if "BEGIN PGP MESSAGE" in message:
                        try:
                            decrypted = self.gpg.decrypt(
                                message,
                                passphrase=(self.app.user_passphrase if self.app else None)
                            )
                            logger.debug(f"Decrypted envelope PGP block: {str(decrypted)}")
                            bundle = json.loads(str(decrypted))
                        except Exception as e:
                            logger.error(f"Failed to decrypt or parse envelope: {e}")
                            display_message = f"Failed to decrypt envelope: {e}"
                            bundle = None
                    else:
                        logger.error(f"Failed to load message as JSON and no PGP envelope detected: {e}")
                        display_message = f"Raw: {message} (parse error, or not for you)"
                        bundle = None

                # 2. If we have a bundle, dispatch by type/fields
                if bundle:
                    # Handle roster updates
                    if bundle.get("type") == "roster":
                        members = bundle.get("members", [])
                        logger.info(f"Received (possibly encrypted) roster update: {members}")
                        self.set_room_members(members)
                        continue

                    # Handle chat messages (ciphertexts)
                    if "ciphertexts" in bundle:
                        sender = bundle.get("sender", "unknown")
                        ciphertexts = bundle["ciphertexts"]
                        your_email = self.app.user_email if self.app else None
                        if your_email and your_email in ciphertexts:
                            encrypted_message = ciphertexts[your_email]
                            try:
                                decrypted = decrypt_message(
                                    encrypted_message,
                                    self.app.user_passphrase
                                )
                                display_message = f"{sender}: {decrypted}"
                                logger.info(f"Decrypted chat message for UI: {display_message}")
                            except Exception as e:
                                display_message = f"{sender}: [Failed to decrypt: {e}]"
                                logger.error(display_message)
                        else:
                            display_message = "[No message for your identity in this bundle]"
                            logger.warning(display_message)
                    else:
                        display_message = f"Raw: {message} (unhandled JSON structure)"
                        logger.warning(display_message)


                def update_ui():
                    try:
                        chat_container = self.app.query_one("#chat-container")
                        chat_area = chat_container.query_one(Vertical)
                        chat_area.mount(Label(display_message))
                        logger.info(f"Displayed incoming message: {display_message}")
                    except Exception as e:
                        logger.error(f"Error updating UI from receive_messages():\n{e}\n")

                if display_message and display_message.strip():
                    if self.app:
                        logger.info(f"Displaying chat message: {display_message!r}")
                        self.app.call_from_thread(update_ui)
                    else:
                        logger.warning("No app reference in PGPChatClient; cannot update UI.")
                else:
                    logger.debug(f"No chat display_message to show (value: {display_message!r}); skipping UI update.")

            except Exception as e:
                logger.error(f"Error in receive_messages():\n{e}\n")
                break