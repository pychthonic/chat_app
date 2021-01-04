
import socket
import logging
from concurrent.futures import ThreadPoolExecutor


class ChatServer:
    def __init__(self, host, port):
        self.logger = self._setup_logger()
        self.sock = self._setup_socket(host, port)
        self.connections = {}
   
    def run(self):
        self.logger.info("Chat server is running")
        with ThreadPoolExecutor() as executor:
            while True:
                # block and wait for incoming connections
                # returns a tuple containing a new socket object
                # with the connection and address of the client_socket on the
                # other end
                conn, addr = self.sock.accept()

                username_validated = False

                while not username_validated:

                    username_request = conn.recv(4096).decode()

                    self.logger.debug(f"Received username: {username_request}")

                    if username_request in self.connections.keys():
                        conn.send("Invalid Username".encode("utf-8"))
                    else:
                        self.connections[username_request] = conn
                        username_validated = True
                        conn.send("Username accepted".encode("utf-8"))

                self.logger.debug(
                    f"New Connection: {username_request} @ {addr}")

                self.logger.debug(f"Connections: {self.connections.keys()}")


                executor.submit(self.relay_messages, conn, addr)

    def relay_messages(self, src_conn, src_addr):
        while True:
            data = src_conn.recv(4096)

            for username in self.connections.keys():
                dest_conn = self.connections[username]

                dest_conn.send(data)

            if not data:
                self.logger.warning("No data. Exiting.")
                break

    @staticmethod
    def _setup_socket(host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen()
        return sock


    @staticmethod
    def _setup_logger():
        logger = logging.getLogger('chat_server')
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)
        return logger

if __name__ == "__main__":
    from chats_app.settings import SERVER_HOST, SERVER_PORT
    server = ChatServer(SERVER_HOST, SERVER_PORT)
    server.run()
