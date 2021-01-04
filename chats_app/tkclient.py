import json
import socket
import sys
import threading
import time
import tkinter

from chat_utils import construct_message_packet, load_message_packet

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes



PORT = 5970
SERVER = "127.0.0.1"
ADDRESS = (SERVER, PORT)

class ChatClientGUI:

    def __init__(self):

        self.client_key = RSA.generate(2048)
        self.client_public_key = self.client_key.publickey().export_key()

        self.window_width = 1200
        self.window_height = 1050


            # MOVE THESE LINES TO AFTER IP ADDRESS HAS BEEN REQUESTED:
        self.client_socket = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
        self.client_socket.connect(ADDRESS)




        self.root = tkinter.Tk()

        self.root.protocol('WM_DELETE_WINDOW', self.exit_client)

        self.root.withdraw()

        self.login_screen = tkinter.Toplevel()

        screen_width = self.login_screen.winfo_screenwidth()
        screen_height = self.login_screen.winfo_screenheight()

        self.starting_x_coordinate = (screen_width/2) - (self.window_width/2)
        self.starting_y_coordinate = (screen_height/2) - (self.window_height/2)

        self.geometry_str = (f"{self.window_width}x{self.window_height}+"
                             f"{int(self.starting_x_coordinate)}+"
                             f"{int(self.starting_y_coordinate)}")
        self.login_screen.geometry(self.geometry_str)
        self.root.geometry(self.geometry_str)

        self.login_screen.title("LOGIN TO CHATWORLD")
        self.login_screen.resizable(width=True,
                                    height=True)

        self.login_screen.configure(width=self.window_width,
                                    height=self.window_height)

        ########### IP ADDRESS ENTRY DESCRIPTION:

        self.ip_label_name = tkinter.Label(self.login_screen,
                                        text="Server IP: ",
                                        font="Helvetica 14 bold")

        self.ip_label_name.place(relheight=0.2,
                              relx=0.1,
                              rely=0.2)

        ########### IP ADDRESS ENTRY:

        self.ip_input = tkinter.Entry(self.login_screen,
                                      justify=tkinter.CENTER,
                                      font="Helvetica 14")

        self.ip_input.bind("<Return>",
                           self.on_login_enter)

        self.ip_input.place(relwidth=0.4,
                            relheight=0.08,
                            relx=0.32,
                            rely=0.2)

        ########### USERNAME ENTRY DESCRIPTION:

        self.username_label_name = tkinter.Label(self.login_screen,
                                        text="Username: ",
                                        font="Helvetica 14 bold")

        self.username_label_name.place(relheight=0.2,
                              relx=0.1,
                              rely=0.35)

        ########### USERNAME ENTRY:

        self.entry_name = tkinter.Entry(self.login_screen,
                                        justify=tkinter.CENTER,
                                        font="Helvetica 14")

        self.entry_name.bind("<Return>",
                            self.on_login_enter)

        self.entry_name.place(relwidth=0.4,
                              relheight=0.08,
                              relx=0.32,
                              rely=0.4)

        self.entry_name.focus()


        ########### SUBMIT BUTTON:

        self.submit_button = tkinter.Button(
            self.login_screen,
            text="CONTINUE",
            font="Helvetica 14 bold",
            command=lambda: self.validate_username(self.entry_name.get())
        )

        self.submit_button.place(relx=0.4,
                                 rely=0.65)


        ########### FEEDBACK LABEL:

        self.username_feedback_message = tkinter.StringVar()

        self.feedback_label = tkinter.Label(
                self.login_screen,
                textvariable=self.username_feedback_message,
                font="Helvetica 14 bold")

        self.feedback_label.place(relheight=0.15,
                                  relx=0.22,
                                  rely=0.8)

        self.root.mainloop()

    def exit_client(self):
        self.client_socket.close()
        self.root.quit()
        self.root.destroy()
        print('Exiting.')
        sys.exit()

    def on_login_enter(self, event):
        username = self.entry_name.get()
        self.validate_username(username)

    def validate_username(self, name):

        if not name.isalnum() or len(name) < 3 or len(name) > 15:
            self.username_feedback_message.set("Username must be letters or "
                                               "numbers \nand between 3 and "
                                               "15 characters.")
            self.root.update_idletasks()
            return

        message = construct_message_packet(
                content=name,
                message_type="RequestUsername",
                recipient="Server",
                public_key=self.client_public_key.decode())
        self.client_socket.send(message)

        validation_response = load_message_packet(
                self.client_socket.recv(4096))

        if validation_response["Content"] == "Invalid Username":
            self.username_feedback_message.set("Username already taken.")
            self.root.update_idletasks()
            return
        elif validation_response["Content"] == "Username Accepted":

            self.server_client_list = json.loads(load_message_packet(
                    self.client_socket.recv(4096)
                )["Content"])
            client_list_ack = construct_message_packet(
                "Client List Received",
                "UpdateConnectionsList",
                "Server"
            )
            self.client_socket.send(client_list_ack)


        self.login_screen.destroy()
        self.layout(name)

        rcv = threading.Thread(target=self.receive)
        rcv.daemon = True

        rcv.start()

    def layout(self, name):

        self.name = name
        self.root.deiconify()
        self.root.title("WELCOME TO CHATWORLD")
        self.root.resizable(width=True,
                            height=True)
        self.root.configure(width=self.window_width,
                            height=self.window_height,
                            bg="#17202A")

        self.label_head = tkinter.Label(self.root,
                                        bg="#17202A",
                                        fg="#EAECEE",
                                        text=self.name,
                                        font="Helvetica 13 bold",
                                        pady=5)

        self.label_head.place(relwidth=1)
        self.line = tkinter.Label(self.root,
                                  width=450,
                                  bg="#ABB2B9")

        self.line.place(relwidth=1,
                        rely=0.07,
                        relheight=0.012)

        self.text_connections = tkinter.Text(self.root,
                                             width=20,
                                             height=2,
                                             bg="#17202A",
                                             fg="#EAECEE",
                                             font="Helvetica 14",
                                             padx=5,
                                             pady=5)

        self.text_connections.place(relheight=0.745,
                                    relwidth=1,
                                    rely=0.08)

        self.label_bottom = tkinter.Label(self.root,
                                          bg="#ABB2B9",
                                          height=80)

        self.label_bottom.place(relwidth=1,
                                rely=0.825)

        self.entry_msg = tkinter.Entry(self.label_bottom,
                                       bg="#2C3E50",
                                       fg="#EAECEE",
                                       font="Helvetica 13")

        self.entry_msg.place(relwidth=0.74,
                             relheight=0.06,
                             rely=0.008,
                             relx=0.011)

        self.entry_msg.focus()

        self.entry_msg.bind("<Return>",
                            self.on_message_enter)

        self.button_msg = tkinter.Button(self.label_bottom,
                                         text="Send",
                                         font="Helvetica 10 bold",
                                         width=20,
                                         bg="#ABB2B9",
                                         command=lambda: self.send_button(
                                            self.entry_msg.get()))

        self.button_msg.place(relx=0.77,
                              rely=0.008,
                              relheight=0.06,
                              relwidth=0.22)

        self.text_connections.config(cursor="arrow")

        scrollbar = tkinter.Scrollbar(self.text_connections)

        scrollbar.place(relheight=1,
                        relx=0.974)

        scrollbar.config(command=self.text_connections.yview)

        self.text_connections.config(state=tkinter.DISABLED)

    def on_message_enter(self, event):
        msg = self.entry_msg.get()
        self.send_button(msg)

    def send_button(self, msg):
        self.text_connections.config(state=tkinter.DISABLED)
        self.msg = msg
        self.entry_msg.delete(0, tkinter.END)
        time.sleep(.1)
        snd = threading.Thread(target=self.send_message)
        snd.daemon = True
        snd.start()

    def receive(self):
        while True:
            try:
                print("receiving...")
                time.sleep(.1)
                message = self.client_socket.recv(4096)

                received_message = load_message_packet(message)

                if received_message["Type"] == "message":

                    message = load_message_packet(message)["Content"]

                    if received_message["Encrypted"]:
                        key_size = self.client_key.size_in_bytes()
                        received_string = message.encode('ISO-8859-1')
                        received_enc_session_key = received_string[0:key_size]
                        received_nonce = received_string[
                                key_size:key_size + 16]
                        received_tag = received_string[
                                key_size + 16:key_size + 32]
                        received_ciphertext = received_string[key_size + 32:]

                        cipher_rsa = PKCS1_OAEP.new(self.client_key)
                        session_key = cipher_rsa.decrypt(
                                received_enc_session_key)

                        cipher_aes = AES.new(session_key, AES.MODE_EAX,
                                             received_nonce)

                        message = cipher_aes.decrypt_and_verify(
                            received_ciphertext, received_tag).decode()

                    # insert messages to text box
                    self.text_connections.config(state=tkinter.NORMAL)
                    self.text_connections.insert(tkinter.END,
                                                 message + "\n")

                    self.text_connections.config(state=tkinter.DISABLED)
                    self.text_connections.see(tkinter.END)

                elif received_message["Type"] == "UpdateConnectionsList":
                    self.server_client_list = json.loads(
                        received_message["Content"])
                    self.client_socket.send("Received".encode("utf-8"))
                    print(f"new client list: {self.server_client_list}")
            except Exception as e:
                print(f"An error occurred: {e}")
                self.client_socket.close()
                break

    # function to send messages
    def send_message(self):
        print("sending...")
        self.text_connections.config(state=tkinter.DISABLED)   ## ????? WHY?

        message = (f"{self.name}> {self.msg}")
        for user in self.server_client_list.keys():
            time.sleep(.1)

            # ENCRYPT MESSAGE HERE:
            pub_key = RSA.import_key(self.server_client_list[user])
            session_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(pub_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(
                message.encode("utf-8"))

            message_content = (enc_session_key
                               + cipher_aes.nonce
                               + tag
                               + ciphertext)

            message_packet = construct_message_packet(
                message_content.decode('ISO-8859-1'),
                "message",
                user,
                encrypted=True
            )
            self.client_socket.send(message_packet)



if __name__ == "__main__":

    ChatClientGUI()
