import json
import socket
import threading
import time

from chat_utils import construct_message_packet, load_message_packet

"""

NOTES:
I'll need to make the server or client or both check for sneaky messages
that have dictionary key/value pairs inside them that match up with
keys that I check for. Also see if I can hack the server that way before
I fix this, for curiosity's sake.

Need to make a queue-handler.

When someone leaves chat, the server sends an updated client list to
each client.

"""

PORT = 5970
SERVER = "127.0.0.1"
ADDRESS = (SERVER, PORT)


class ChatServer:
    def __init__(self):

        self.connections = {}
        self.connection_dict_for_clients = {}

        self.server_socket = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET,
                                      socket.SO_REUSEADDR,
                                      1)
        self.server_socket.bind(ADDRESS)
        print("Server started on " + SERVER)
        self.server_socket.listen()

        while True:
            conn, addr = self.server_socket.accept()

            username_validated = False

            while not username_validated:
                name_message = load_message_packet(conn.recv(4096))
                if name_message["Type"] == "RequestUsername":

                    if name_message["Content"] in self.connections.keys(): # MAKE THIS CHECK
                                                                            # FOR PUBLIC KEY TOO!
                        message = construct_message_packet(
                            "Invalid Username",
                            "RequestUsername",
                            "phoney_" + name_message["Content"]
                        )
                        conn.send(message)
                    else:
                        message = construct_message_packet(
                            "Username Accepted",
                            "RequestUsername",
                            name_message["Content"]
                        )
                        conn.send(message)
                        new_client_public_key = name_message["Public Key"]
                        self.connections[name_message["Content"]] = {
                            "connection": conn,
                            "public_key": new_client_public_key
                        }
                        self.connection_dict_for_clients[
                            name_message["Content"]] = new_client_public_key

                        username_validated = True
                        print(f"{name_message['Content']} has connected. "
                              f"Public Key: {new_client_public_key}")

                        ######### NEED 2 LISTS OF CONNECTIONS. ###########

                        for client in self.connections.keys():
                            conn_list_message = construct_message_packet(
                                json.dumps(self.connection_dict_for_clients),
                                "UpdateConnectionsList",
                                client
                            )
                            self.connections[
                                client]["connection"].send(conn_list_message)
                            received_ack = self.connections[
                                client]["connection"].recv(4096)


            welcome_message = (f"{name_message['Content']} has joined the "
                               f"chat.\nChatroom members: ")
            for username in self.connections.keys():
                welcome_message += username + ", "
            welcome_message = welcome_message[:-2]
            welcome_message = construct_message_packet(
                welcome_message,
                "message",
                name_message["Content"]
            )

            self.broadcast_message(welcome_message)

            thread = threading.Thread(target=self.message_handler,
                                      args=(name_message["Content"],))
            thread.start()

            print(f"There are now {threading.activeCount() - 1} active "
                  f"connections.")

    def message_handler(self, username: str) -> None:
        print(f"{username} has joined the chat")

        connected = True
        while connected:
            time.sleep(.1)
            message = self.connections[username]["connection"].recv(4096)
            if not message:
                connected = False
                message = f"{username} has left the chat."
                message = construct_message_packet(message, "message")
                self.broadcast_message(message)
            else:
                received_message = load_message_packet(message)
                if received_message["Type"] == "message":
                    recipient = received_message["Recipient"]
                    if recipient == "Broadcast":
                        self.broadcast_message(
                            received_message["Content"].encode("utf-8"))
                    else:
                        recipient_conn = self.connections[
                            recipient]["connection"]
                        recipient_conn.send(message)
                        #msg_ack = recipient_conn.recv(4096)


        # REMOVE USER FROM CONNECTIONS LIST:

        self.connections[username]["connection"].close()
        del self.connections[username]
        del self.connection_dict_for_clients[username]

        for client in self.connections.keys():
            conn_list_message = construct_message_packet(
                json.dumps(self.connection_dict_for_clients),
                "UpdateConnectionsList",
                client
            )
            self.connections[
                client]["connection"].send(conn_list_message)
            received_ack = self.connections[
                client]["connection"].recv(4096)


    def broadcast_message(self, message):
        for username in self.connections.keys():
            self.connections[username]["connection"].send(message)


if __name__ == "__main__":
    ChatServer()
