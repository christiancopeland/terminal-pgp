import threading 
import socket 
import logging
import json
import ssl


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
        self.hosting_room_name = ""
        self.app = app
        self.server_socket = None
        self.client_socket = None
        self.ready_event = threading.Event()
        self.sender_email = None
        self.recipient_email = None
        self.passphrase = None

        self.clients_email_map = {}

        logger.debug(f"PGPChatServer initialized on host {self.host} and port {self.port}")

    def start_server(self):
        logger.info("Attempting to start the PGP chat server.")
        ## Attempting to implement secure sockets with TLS Certificates
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        context.set_ciphers('ECDHE+AESGCM')
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            logger.info(f"Server successfully bound to {self.host}:{self.port}")
            self.server_socket.listen()
            logger.info(f"Server is listening on {self.host}:{self.port}")
            self.ready_event.set()
        except Exception as e:
            logger.error(f"Failed to bind/listen on {self.host}:{self.port}: {e}")
            return

        while True:
            try:
                client_socket, address = self.server_socket.accept()
                secure_socket = context.wrap_socket(client_socket, server_side=True)
                logger.info(f"Accepted connection from {address}")
                self.clients.append(secure_socket)
                logger.info(f"Current clients: {[c.getpeername() for c in self.clients if c]}")

                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(secure_socket,),
                    daemon=True
                )
                client_handler.start()
                logger.debug(f"Client handler thread started for {address}")
            except Exception as e:
                logger.error(f"Error in start_server():\n{e}\n")
    
    def start_server_in_thread(self):
        try:
            # server = PGPChatServer('0.0.0.0', self.port, app=self.app)
            logger.info(f"Hosting room {self.hosting_room_name} on port {self.port}.")
            self.start_server()
        except Exception as e:
            logger.error(f"Error in start_server_in_thread():\n{e}\n")
            raise

    def handle_client(self, client_socket):
        address = None
        try:
            address = client_socket.getpeername()
            logger.info(f"Started handler for client {address}")
        except Exception:
            logger.warning("Could not retrieve client address.")

        identity_received = False
        while True:
            try:
                message = client_socket.recv(4096)
                if not message:
                    logger.info(f"Client {address} disconnected. Removing client.")
                    self.remove_client(client_socket)
                    break
                logger.debug(f"Received message from client {address}: {json.loads(message)}")
                try:
                    bundle = json.loads(message)
                except Exception as e:
                    logger.error(f"Could not decode JSON in handle_client(): {e}")
                    continue
                # Expect first message to be identity
                if not identity_received:
                    if bundle.get("type") == "identity" and "email" in bundle:
                        self.clients_email_map[client_socket] = bundle["email"]
                        self.broadcast_roster()
                        identity_received = True
                        logger.info(f"Registered identity {bundle['email']} from {address}")
                        continue  # Wait for next real message
                    else:
                        logger.warning("First message from client was not a valid identity. Disconnecting.")
                        client_socket.close()
                        return
                # Ignore any further identity messages
                if bundle.get("type") == "identity":
                    logger.warning(f"Unexpected identity message from {address}. Ignoring.")
                    continue
                # Handle chat/data messages as normal
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

    def broadcast_roster(self):
        roster = [email for email in self.clients_email_map.values()]
        roster_message = json.dumps({"type": "roster", "members": roster})
        for sock in list(self.clients_email_map.keys()):
            try:
                sock.sendall(roster_message.encode('utf-8'))
                logger.debug(f"Sent roster update to {sock}")
            except Exception as e:
                logger.error(f"Error sending roster to client in broadcast_roster(): {e}")

    def remove_client(self, client_socket):
        try:
            address =  client_socket.getpeername()
        except Exception:
            address = "<unknown>"
        try:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            if client_socket in self.clients_email_map:
                del self.clients_email_map[client_socket]
            client_socket.close()
            logger.info(f"Removed and closed connection for client {address}. Remaining clients: {len(self.clients)}")
            self.broadcast_roster()
        except Exception as e:
            logger.error(f"Error removing client {address}: {e}")
