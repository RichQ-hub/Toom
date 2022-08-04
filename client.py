# Version: Python 3.10.5 (Which should work for 3.7 on CSE machines)

import os
import pickle
import sys
from socket import *
import textwrap
from threading import Thread

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 2000
SERVER_ADDRESS = (SERVER_HOST, SERVER_PORT)

CLIENT_HOST = '127.0.0.1'
HEADER = 1024

# ----------------------------------------------------------------
# UDP client thread.
# ----------------------------------------------------------------

class UDPClientThread(Thread):
    def __init__(self, client_socket, receiver_address, filename, user):
        Thread.__init__(self)
        self.client_socket = client_socket
        self.receiver_address = receiver_address
        self.filename = filename
        self.user = user

    def run(self):
        # Send initial details of the user and file being sent to the audience client.
        message = {
            "filename": self.filename,
            "user": self.user,
        }
        message = pickle.dumps(message)
        self.client_socket.sendto(message, self.receiver_address)

        print(f"sending {self.filename}")

        # Open the file and send 1024 bytes at a time.
        with open(self.filename, "rb") as stream:
            file_data = stream.read(HEADER)

            while file_data:
                if self.client_socket.sendto(file_data, self.receiver_address):
                    file_data = stream.read(HEADER)

        # Send no bytes to indicate the end of the file.
        self.client_socket.sendto(b'', self.receiver_address)


# ----------------------------------------------------------------
# UDP server thread.
# ----------------------------------------------------------------

class UDPServerThread(Thread):
    def __init__(self, server_socket):
        Thread.__init__(self)
        self.server_socket = server_socket

    def run(self):
        while True:
            # Receive initial details of the user and file being sent to this client.
            presenter_details = pickle.loads(self.server_socket.recvfrom(2048)[0])

            if not presenter_details:
                break

            user = presenter_details["user"]
            filename = presenter_details["filename"]

            new_filename = f"{user}_{filename}"
            
            # Create a new file and write 1024 bytes at a time into the file.
            with open(new_filename, "wb") as stream:
                file_data = self.server_socket.recvfrom(HEADER)[0]

                while file_data:
                    stream.write(file_data)
                    file_data = self.server_socket.recvfrom(HEADER)[0]

            print(f"\nDownloaded {filename} from {user} as {new_filename}\n")
                

# ----------------------------------------------------------------
# Handle UDP command.
# ----------------------------------------------------------------

def handle_command_UDP(user, command, command_args):

    # Assert correct usage of the command.
    if len(command_args) != 2:
        print("[USAGE] UDP <username> <filename>")
        return

    audience_username = command_args[0]
    filename = command_args[1]

    # Assert the filename exists. 
    if not os.path.exists(filename):
        print(f"[ERROR] {filename} does not exist in the current directory.")
        return

    # Obtain audience user details. 
    request = create_command_request(user, command, command_args)

    # Send request.
    clientSocket.sendall(pickle.dumps(request))

    # Get response.
    response = clientSocket.recv(HEADER)
    response = pickle.loads(response)

    audience_user = response["data"]

    if not audience_user:
        print(f"{audience_username} is not active.")
        return
    
    audience_IP = audience_user["IP_address"]
    audience_UDP_server_port = audience_user["UDP_socket_port"]

    UDP_client_thread = UDPClientThread(UDP_server_socket, (audience_IP, audience_UDP_server_port), filename, user)
    UDP_client_thread.start()


# ----------------------------------------------------------------
# Authentification methods.
# ----------------------------------------------------------------

def process_login():
    # Handle username.
    while True:
        # Obtain and send username.
        username = input("Username: ")

        if not username:
            print("No username supplied. Please try again")
            continue

        clientSocket.sendall(username.encode())

        # Recieve username validity.
        username_is_valid = clientSocket.recv(HEADER)
        username_is_valid = pickle.loads(username_is_valid)

        if username_is_valid:
            break

        print("Unknown username. Please try again")

    # Recieve user timeout status.
    user_blocked = clientSocket.recv(HEADER)
    user_blocked = pickle.loads(user_blocked)

    if user_blocked:
        print("User has been blocked. Please try again later")
        close_client() 

    # Handle password.
    while True:
        # Obtain and send password.
        password = input("Password: ")
        clientSocket.sendall(password.encode())

        # Receive password validity.
        password_status = clientSocket.recv(HEADER)
        password_status = pickle.loads(password_status)

        if not password_status["password_is_valid"] and password_status["blocked"]:
            print("Invalid Password. You have been blocked")
            close_client()

        if password_status["password_is_valid"]:
            break

        print("Invalid Password. Please try again")

    # Authentication was a success.
    send_UDP_socket()

    # Receive login status.
    login_success = clientSocket.recv(HEADER)
    login_success = pickle.loads(login_success)
    if not login_success:
        print("User already logged in.")
        close_client()

    print("Welcome to Toom!")
    print()

    return username

def send_UDP_socket():
    clientSocket.sendall(pickle.dumps(UDP_server_port_number))


# ----------------------------------------------------------------
# Start function.
# ----------------------------------------------------------------

def create_request(type, user, data):
    request = {
        "type": type,
        "user": user,
        "data": data,
    }
    return request

def create_command_request(user, command, command_args):
    command_data = {
        "command": command,
        "command_args": command_args,
    }
    return create_request("command", user, command_data)

def start():
    """Starts the client.
    """

    # First receive authentification request from the server. 
    data = clientSocket.recv(HEADER)
    response = pickle.loads(data)

    if response["request_type"] == "login":
        username = process_login()

    client_alive = True
    while client_alive:
        print("==========================================================================")
        print("Enter one of the following commands (BCM, ATU, SRB, SRM, RDM, UDP, OUT):")
        command = input(">> ")

        # If no command was supplied.
        if not command:
            print("No command supplied")
            continue

        # Send command request.
        command_type = command.split()[0]
        command_args = command.split()[1:]

        # If UDP command:
        if command_type == "UDP":
            handle_command_UDP(username, command_type, command_args)
            continue

        request = create_command_request(username, command_type, command_args)

        # Send request.
        clientSocket.sendall(pickle.dumps(request))

        # Get response.
        response = clientSocket.recv(HEADER)
        response = pickle.loads(response)

        print_response(response)

        if not response["keep_alive"]:
            client_alive = False
    
    close_client()

def print_response(response):
    cmd = response['command']

    print(textwrap.dedent(f"""
    -- [{cmd}] Response ---------------------------------------------------
    
    Status: {response['status']}
    For: {response['user']}

    {response['data']}

    ---------------------------------------------------------------------
    """))

def close_client():
    # Close UDP server thread.
    UDP_server_socket.sendto(pickle.dumps(None), (CLIENT_HOST, UDP_server_port_number))
    
    clientSocket.close()
    UDP_server_socket.close()
    sys.exit(0)

# ----------------------------------------------------------------
# Main function.
# ----------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <client-udp-port>")
        sys.exit(1)

    UDP_server_port_number = int(sys.argv[1])

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(SERVER_ADDRESS)

    UDP_server_socket = socket(AF_INET, SOCK_DGRAM)
    UDP_server_socket.bind((CLIENT_HOST, UDP_server_port_number))

    # Start client UDP server.
    UDP_server_thread = UDPServerThread(UDP_server_socket)
    UDP_server_thread.start()

    # Start client.
    start()