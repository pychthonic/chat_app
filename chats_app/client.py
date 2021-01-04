import datetime

import socket

from threading import Thread

class ChatClient:
    def __init__(self, host, port):
        pass

    def send_message(self):
        while True:
            user_message = input("> ")
            timestamp = datetime.datetime.now().strftime("%I:%M:%S %p")

            full_message = (timestamp
                            + " | "
                            + self.username
                            + "> "
                            + user_message)
            self.sock.send(full_message.encode("utf-8", "backslashreplace"))

    def get_unique_username(self):
        while True:
            self.username = input("Enter Username: ")
            if len(self.username) > 15 or not self.username.isalnum():
                self.logger.debug("Username must be letters or numbers and "
                                  "less than 15 characters.")
                continue

            self.sock.send(self.username.encode("utf-8"))
            username_response = self.sock.recv(4096).decode()
            if username_response == "Invalid Username":
                self.logger.debug("Invalid Username")
                continue
            else:
                break



    # @staticmethod
    # def _setup_logger():
    #     logger = logging.getLogger("chat_client")
    #     logger.addHandler(logging.StreamHandler())
    #     logger.setLevel(logging.DEBUG)
    #     return logger

if __name__ == "__main__":
    from chats_app.settings import SERVER_HOST, SERVER_PORT
    client = ChatClient(SERVER_HOST, SERVER_PORT)
