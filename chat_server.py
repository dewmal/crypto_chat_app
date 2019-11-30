#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread


def get_user_public_key(username):
    for sock in clients:
        client_data = clients[sock]
        if client_data["name"] == username:
            return sock, client_data


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Greetings from the cave! Now type your name and press enter!", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""

    welcome_message = client.recv(BUFSIZ).decode("utf8")
    welcome_message = welcome_message.split(":")
    name = welcome_message[2]
    clients[client] = {
        "name": name,
        "key": welcome_message[3]
    }
    while True:
        raw_msg = client.recv(BUFSIZ)
        print(raw_msg)
        # Process System Messages
        if raw_msg.decode("utf8").startswith("SYS"):
            raw_msg = raw_msg.decode("utf8")
            # print(raw_msg)
            raw_msg = raw_msg.split(":")
            command = raw_msg[1]
            value = raw_msg[2]
            # print(command, value)
            if command == "REQUEST_USER_KEY":
                sock, user_data = get_user_public_key(username=value)
                if user_data:
                    client.send(bytes(f"SYS:{user_data['key']}", "utf8"))
                    session_key = client.recv(BUFSIZ).decode("utf8").replace("SYS:ENCRYPTED_SESSION_KEY:", "")
                    signature = client.recv(BUFSIZ).decode("utf8").replace("SYS:SIGNATURE:", "")

                    my_user_data = clients[client]

                    sock.send(bytes(f"SYS:CLIENT_PUBLIC_KEY:{my_user_data['key']}", "utf8"))
                    sock.send(bytes(f"SYS:CLIENT_ENCRYPTED_SESSION_KEY:{session_key}", "utf8"))
                    sock.send(bytes(f"SYS:CLIENT_SIGNATURE:{signature}", "utf8"))
                else:
                    client.send(bytes(f"SYS:NONE", "utf8"))

        else:
            msg = ""
            print(msg)

            if msg != bytes("{quit}", "utf8"):
                broadcast(msg, name + ": ")
            else:
                client.send(bytes("{quit}", "utf8"))
                client.close()
                del clients[client]
                broadcast(bytes("%s has left the chat." % name, "utf8"))
                break


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    print(type(msg))
    print(type(prefix))
    for sock in clients:
        sock.send(bytes(prefix, "utf8") + bytes(msg, "utf8"))


clients = {}
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
