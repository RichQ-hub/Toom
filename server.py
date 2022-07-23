# Version: Python 3.10.5 (Which should work for 3.7 on CSE machines)

from datetime import datetime
from pprint import pprint
import re
import sys
from socket import *
from threading import Thread
import pickle
from turtle import down
from server_data import ServerData

import validate

HOST = '127.0.0.1'
PORT = 2000
ADDRESS = (HOST, PORT)
HEADER = 1024 # Size of each TCP segment.

class ClientThread(Thread):
    """A new Thread object is created for each new client. 
    """

    # Class Constructor.
    def __init__(self, clientAddress, clientSocket, server_data):
        Thread.__init__(self) # A new thread is created when this class is instantiated.
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False

        # Server data.
        self.server_data = server_data
        
        print("===== New connection created for: ", clientAddress)
        self.clientAlive = True

    # ----------------------------------------------------------------
    # Driver function.
    # ----------------------------------------------------------------

    def run(self):
        """Driver code for the 
        """
        # This method is implicitly run after calling clientThread.start().
        if not self.authenticate_client():
            return
        
        pprint(self.server_data.get_active_users())
        
        # Handle Commands.
        while self.clientAlive:
            request = self.clientSocket.recv(HEADER)

            # If the message from client is empty, the client would have disconnected.
            if not request:
                self.clientAlive = False
                break

            # Commands.
            request = pickle.loads(request)
            if request["command_type"] == "OUT":
                self.handle_command_OUT(request)
                self.clientAlive = False
            elif request["command_type"] == "BCM":
                self.handle_command_BCM(request)
            elif request["command_type"] == "ATU":
                self.handle_command_ATU(request)

    # ----------------------------------------------------------------
    # ATU command methods.
    # ----------------------------------------------------------------

    def handle_command_ATU(self, request):
        download_active_users = []
        for user in self.server_data.get_active_users():
            if user["username"] != request["username"]:
                download_active_users.append(user)
        
        response = {
            "command_type": "ATU",
            "active_users": download_active_users,
        }
        self.clientSocket.sendall(pickle.dumps(response))
    
    # ----------------------------------------------------------------
    # BCM command methods.
    # ----------------------------------------------------------------

    def handle_command_BCM(self, request):
        # Generate message id.
        message_id = 1
        if len(self.server_data.get_broadcasted_messages()) != 0:
            message_list = self.server_data.get_broadcasted_messages()
            message_id = message_list[-1]["message_id"] + 1

        current_time = datetime.now()
        broadcast_msg = {
            "username": request["username"],
            "message_id": message_id,
            "timestamp": current_time,
            "message": request["message"],
        }
        self.server_data.create_broadcasted_message(broadcast_msg)

        response = {
            "command_type": "BCM",
            "message_id": message_id,
            "timestamp": self.convert_datetime_to_timestamp(current_time)
        }
        self.clientSocket.sendall(pickle.dumps(response))

        # Create a message log.
        self.create_message_log(broadcast_msg) 

        # Print command request to server output.
        print("[BCM] =======================")
        pprint(broadcast_msg)
        print("=============================")

    def create_message_log(self, broadcast_msg):
        message_id = broadcast_msg["message_id"]
        timestamp = self.convert_datetime_to_timestamp(broadcast_msg["timestamp"])
        username = broadcast_msg["username"]
        message = broadcast_msg["message"]

        with open("messagelog.txt", "a") as stream:
            stream.write(f"{message_id}; {timestamp}; {username}; {message}\n")

    # ----------------------------------------------------------------
    # OUT command methods.
    # ----------------------------------------------------------------

    def handle_command_OUT(self, request):
        self.server_data.delete_active_user(request["username"])
        self.delete_user_log(request)

        pprint(self.server_data.get_active_users())

        print(f"> {request['username']} has logged out")

        response = {
            "status": f"{request['username']} has successfully logged out",
        }
        self.clientSocket.sendall(pickle.dumps(response))      
    
    # ----------------------------------------------------------------
    # Authentification methods.
    # ----------------------------------------------------------------

    def authenticate_client(self):
        # Send login request.
        input_login_attempts = int(sys.argv[1])
        msg = {
            "request_type": "login",
        }
        self.clientSocket.sendall(pickle.dumps(msg))

        # Authenticate client username.
        while True:
            username = self.clientSocket.recv(HEADER).decode()
            username_is_valid = self.server_data.valid_username(username)

            self.clientSocket.sendall(pickle.dumps(username_is_valid))

            if username_is_valid:
                break

        # Check if user has been blocked.
        user_blocked = self.server_data.user_is_blocked(username)
        print(user_blocked)
        self.clientSocket.sendall(pickle.dumps(user_blocked))
        if user_blocked:
            return False

        # Authenticate password for current client.
        blocked = False
        attempts = 1
        while True:
            password = self.clientSocket.recv(HEADER).decode()
            password_is_valid = self.server_data.valid_user(username, password)
            
            if not password_is_valid:
                if attempts == input_login_attempts:
                    blocked = True

            msg = {
                "password_is_valid": password_is_valid,
                "blocked": blocked,
            }
            self.clientSocket.sendall(pickle.dumps(msg))

            if blocked:
                self.server_data.block_user_login(username)
                return False
            if password_is_valid:
                break

            attempts += 1

        # User info verification success.

        # Receive user UDP port.
        user_UDP_socket_port = self.clientSocket.recv(HEADER)
        user_UDP_socket_port = pickle.loads(user_UDP_socket_port)

        # Login the user (create an active user).
        login_success = self.login_user(username, user_UDP_socket_port)
        self.clientSocket.sendall(pickle.dumps(login_success))

        return login_success

    def login_user(self, username, user_UDP_socket_port):
        
        login_timestamp = self.convert_datetime_to_timestamp(datetime.now())

        new_active_user = {
            "username": username,
            "login_timestamp": login_timestamp,
            "UDP_socket_port": user_UDP_socket_port,
            "IP_address": self.clientAddress[0],
        }
        login_success = self.server_data.create_active_user(new_active_user)

        if login_success:
            print(f"{username} has logged in.")
            self.create_user_log(new_active_user)
        else:
            print(f"{username} has failed to login.")

        return login_success

    # ----------------------------------------------------------------
    # Helpers.
    # ----------------------------------------------------------------

    def create_user_log(self, active_user):
        with open("userlog.txt", "r") as stream:
            lines = stream.readlines()

        # Obtain next user sequence number.
        try:
            last_line = lines[-1]
        except IndexError as e:
            last_line = None

        next_seq_num = 1
        if last_line:
            last_seq_num = int(last_line.split(";")[0])
            next_seq_num = last_seq_num + 1

        # Obtain relevant active_user details. 
        timestamp = active_user["login_timestamp"]
        username = active_user["username"]
        IP_address = active_user["IP_address"]
        UDP_socket_port = active_user["UDP_socket_port"]

        with open("userlog.txt", "a", encoding="utf-8") as stream:
            stream.write(f"{next_seq_num}; {timestamp}; {username}; {IP_address}; {UDP_socket_port}\n")

    def delete_user_log(self, request):
        with open("userlog.txt", "r") as stream:
            lines = stream.readlines()

        # Remove the relevant user.
        removed_line = ""
        for line in lines:
            log_line = re.split(r"; ", line)
            log_username = log_line[2]
            if log_username == request["username"]:
                removed_line = line
                break

        lines.remove(removed_line)

        # Update seq numbers.
        seq_number = 1
        for i, line in enumerate(lines):
            lines[i] = re.sub(r"^\d+", str(seq_number), line, count=1)
            seq_number += 1

        with open("userlog.txt", "w") as stream:
            for line in lines:
                stream.write(line)

    def convert_datetime_to_timestamp(self, date_time):
        day = date_time.strftime("%d")
        month = date_time.strftime("%b")
        year = date_time.strftime("%Y")
        hour = date_time.strftime("%H")
        minute = date_time.strftime("%M")
        seconds = date_time.strftime("%S")

        return f"{day} {month} {year} {hour}:{minute}:{seconds}"

# ----------------------------------------------------------------
# Start function.
# ----------------------------------------------------------------

def start():
    """Starts the server, accepting new TCP connections.
    """
    server_data = ServerData()

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(ADDRESS)
    serverSocket.listen()

    print("Server is now running")

    while True:
        clientSockt, clientAddress = serverSocket.accept()
        clientThread = ClientThread(clientAddress, clientSockt, server_data)
        clientThread.start()

# ----------------------------------------------------------------
# Main function.
# ----------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <login-attempts>")
        sys.exit(1)

    # Check login_attempts is of type int.
    if not validate.validate_login_attempts_number(sys.argv[1]):
        print("<login-attempts> must be a number between 1 and 5")
        sys.exit(1)

    # Start server.
    start()

