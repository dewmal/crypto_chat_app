#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import crypto

key = None
global_data = {
    "session_key": None
}


def receive():
    """Handles receiving of messages."""
    client_encrypted_session_key = None
    client_signature = None
    client_public_key = None
    is_session_key_trusted = False
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")

            if msg.startswith("SYS:"):
                if msg.startswith("SYS:CLIENT_PUBLIC_KEY:"):
                    client_public_key = bytes(msg.replace("SYS:CLIENT_PUBLIC_KEY:", ""), "utf8")
                if msg.startswith("SYS:CLIENT_ENCRYPTED_SESSION_KEY:"):
                    client_encrypted_session_key = msg \
                        .replace("SYS:CLIENT_ENCRYPTED_SESSION_KEY:", "")
                    client_encrypted_session_key = bytes.fromhex(client_encrypted_session_key)
                if msg.startswith("SYS:CLIENT_SIGNATURE:"):
                    client_signature = msg.replace("SYS:CLIENT_SIGNATURE:", "")
                    client_signature = bytes.fromhex(client_signature)

            if client_encrypted_session_key and client_signature and client_public_key and not global_data[
                "session_key"]:
                session_key = crypto.decrypt_session_key(client_encrypted_session_key,
                                                         my_rsa_key.export_key())
                is_session_key_trusted = crypto.verify_message_signature(client_public_key,
                                                                         session_key, client_signature)
                if is_session_key_trusted:
                    global_data["session_key"] = session_key
                    print("Client accept session key")
                continue
            if global_data["session_key"]:
                msg_data = msg.split(":")
                # print(msg_data)
                decrypt_msg = crypto.decypt_message(global_data["session_key"], bytes.fromhex(msg_data[1]),
                                                    bytes.fromhex(msg_data[2]), bytes.fromhex(msg_data[3]))
                hash_decrypt_msg = crypto.hash_message(decrypt_msg)
                print(hash_decrypt_msg)
                print(bytes.fromhex(msg_data[4]))
                if hash_decrypt_msg.digest() == bytes.fromhex(msg_data[4]):
                    msg_list.insert(tkinter.END, f"{msg_data[0]} : {decrypt_msg}")
                else:
                    msg_list.insert(tkinter.END, "Hash Error")

        except OSError:  # Possibly client has left the chat.
            print(client_encrypted_session_key)
            break


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    nonce, tag, cipher_text = crypto.encypted_message(global_data["session_key"], msg)
    h = crypto.hash_message(msg)
    client_socket.send(bytes(f"{nonce.hex()}:{tag.hex()}:{cipher_text.hex()}:{h.digest().hex()}", "utf8"))
    if msg == "{quit}":
        client_socket.close()
        top.quit()


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()


# ----Now comes the sockets part----
HOST = input('Enter host: ')
PORT = input('Enter port: ')
USERNAME = input('Enter Username: ')
PASSWORD = input('Enter Password: ')
CHAT_USERNAME = input('Chat username: ')

if not HOST:
    HOST = "127.0.0.1"

if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

top = tkinter.Tk()
top.title(f"Chatter {USERNAME}")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
msg = client_socket.recv(BUFSIZ).decode("utf8")
# print(msg)

crypto.make_and_save_user_rsa(passphrase=PASSWORD, username=USERNAME)
my_rsa_key = crypto.load_user_rsa(username=USERNAME, passphrase=PASSWORD)
session_key = crypto.make_session_key()
# print(my_rsa_key)
# print(my_rsa_key.publickey().export_key())
# send encrypted session key and signature to server
pub_key = my_rsa_key.publickey().export_key()
pub_key = pub_key.decode("utf-8")
msg = f"SYS:SHARE_MY_PUBLIC_KEY:{USERNAME}:{pub_key}"
client_socket.send(bytes(msg, "utf8"))

# 4 share session key as encypted message
if CHAT_USERNAME:
    # pass
    client_socket.send(bytes(f"SYS:REQUEST_USER_KEY:{CHAT_USERNAME}", "utf8"))
    raw_msg = client_socket.recv(BUFSIZ).decode("utf8")

    if raw_msg.startswith("SYS:"):
        msg = raw_msg.split(":")
        if msg[1] is not "NONE":
            encrypted_session_key = crypto.encypt_session_key(session_key, msg[1])
            message_signature = crypto.sign_message(my_rsa_key.export_key(), session_key)

            client_socket.send(bytes(f"SYS:ENCRYPTED_SESSION_KEY:{encrypted_session_key.hex()}", "utf8"))
            client_socket.send(bytes(f"SYS:SIGNATURE:{message_signature.hex()}", "utf8"))

            signature = message_signature
            global_data["session_key"] = session_key

            print("Connected with chat application")

print("Chat Start")

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
