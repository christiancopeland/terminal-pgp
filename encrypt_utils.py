import gnupg
import getpass
import logging


# Setup the logger
logging.basicConfig(
    filename="pgp_log",  # Log file name
    level=logging.DEBUG,  # Log all levels of events (DEBUG and above)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
)
logger = logging.getLogger(__name__)  # Create a logger instance


gpg = gnupg.GPG(gnupghome='./pgp_keys')

def generate_key_pair(email, passphrase):
    logger.info(f"Generating key pair for email: {email}")
    input_data = gpg.gen_key_input(
        name_email=email, 
        passphrase=passphrase,
        key_type='RSA',
        key_length=4096,
    )
    key = gpg.gen_key(input_data)
    logger.info(f"Key generated successfully: {key.fingerprint}")
    return key



def encrypt_and_sign_message(sender_fingerprint, sender_passphrase, recipient_fingerprint, message):
    logger.info("Attempting to encrypt a message")
    logger.debug(f"Sender fingerprint: {sender_fingerprint}, Recipient fingerprint: {recipient_fingerprint}")
    # Check if recipient key exists using FINGERPRINT
    if not gpg.list_keys(keys=recipient_fingerprint):
        logger.warning(f"Recipient key not found or untrusted: {recipient_fingerprint}")
        raise ValueError("Recipient key not found or untrusted")
    encrypted_data = gpg.encrypt(
        message, 
        recipients=recipient_fingerprint,
        sign=sender_fingerprint,
        passphrase=sender_passphrase,
        always_trust=False
    )
    if not encrypted_data.ok:
        logger.error(f"Encryption failed: {encrypted_data.status}")
        raise RuntimeError(f"Encryption failed: {encrypted_data.status}")
    logger.info("Message encrypted successfully")
    return str(encrypted_data)



def decrypt_message(encrypted_msg, passphrase):
    logger.info("Attempting to decrypt a message")
    decrypted_data = gpg.decrypt(encrypted_msg, passphrase=passphrase)
    if not decrypted_data.ok:
        logger.error("Decryption failed: Invalid key/passphrase or tampered data")
        raise RuntimeError("Decryption failed: Invalid key/passphrase or tampered data")
    logger.info("Message decrypted successfully")
    return str(decrypted_data)
