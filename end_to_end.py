import gnupg
import getpass
import os
import logging
from io import StringIO

from textual.app import App, ComposeResult
from textual.widgets import Button, Header, Footer, Input, Label, TextArea
from textual.reactive import reactive
from textual.containers import Vertical, VerticalScroll, Horizontal


from encrypt_utils import generate_key_pair, decrypt_message, encrypt_and_sign_message


# Setup the logger
logging.basicConfig(
    filename="pgp_log",  # Log file name
    level=logging.DEBUG,  # Log all levels of events (DEBUG and above)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
)
logger = logging.getLogger(__name__)  # Create a logger instance







def get_key(email):
    pass


class PGPApp(App):
    """A Textual-based terminal front end for your PGP project."""

    CSS_PATH = "./styles.css"

    # Reactive attributes for tracking mode
    mode = reactive("output")

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

            id="buttons-container",
            classes="buttons-row",  # Add CSS class for styling
        )
        yield VerticalScroll(id="input-container")  # Dynamic container for inputs
        yield TextArea(id="output", text="")
        yield Footer()

    # def on_mount(self):
    #     """Add buttons to the buttons container."""
    #     buttons_container = self.query_one("#buttons-container")
    #     buttons_container.mount(Button("Generate Key Pair", id="generate-key"))
    #     buttons_container.mount(Button("Encrypt Message", id="encrypt"))
    #     buttons_container.mount(Button("Decrypt Message", id="decrypt"))
    #     logger.info("Application mounted successfully")

    def watch_mode(self, mode: str):
        """Update input fields dynamically when the mode is changed."""
        input_container = self.query_one("#input-container")
        input_container.remove_children()
        logger.info(f"Switched mode to: {mode}")

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
            input_container.mount(TextArea(name="Enter Encrypted Message", id="decrypt-message"))
            input_container.mount(Input(placeholder="Enter Decryption Passphrase", password=True, id="decrypt-pass"))
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
        
        input_container.refresh()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle mode selection and submission buttons."""
        logger.info(f"Button pressed: {event.button.id}")
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





    # # Generate keys 
    # alice_pass = getpass.getpass("Alice's passphrase: ")
    # alice_key = generate_key_pair("alice@example.com", alice_pass)
    # print(alice_key.fingerprint)
    
    # bob_pass = getpass.getpass("Bob's passphrase: ")
    # bob_key = generate_key_pair("bob@example.com", bob_pass)
    # print(bob_key.fingerprint)

    # print("All keys in keyring:", gpg.list_keys())

    # # Encrypt and sign using FINGERPRINTS 
    # encrypted = encrypt_and_sign_message(
    #     sender_fingerprint=alice_key.fingerprint,
    #     sender_passphrase=alice_pass,
    #     recipient_fingerprint=bob_key.fingerprint,
    #     message="Hello, Bob!"
    # )
    
    # # Decrypt
    # decrypted = decrypt_message(encrypted, bob_pass)
    # print(f"Decrypted: {decrypted}")
