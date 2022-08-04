# Version: Python 3.10.5 (Which should work for 3.7 on CSE machines)

from datetime import datetime
from pprint import pprint
import re
import sys
from socket import *
import textwrap
from threading import Thread
import pickle
from server_data import ServerData

import validate

HOST = '127.0.0.1'
HEADER = 1024 # Size of each TCP segment.

SUCCESS = "Success"
FAILURE = "Failure"

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
        """Driver code handling the server-side process of the TCP connection.
        """
        # This method is implicitly run after calling clientThread.start().
        if not self.authenticate_client():
            return
        
        # pprint(self.server_data.get_active_users())
        
        # Handle Commands.
        while self.clientAlive:
            request = self.clientSocket.recv(HEADER)

            # If the message from client is empty, the client would have disconnected.
            if not request:
                self.clientAlive = False
                break

            request = pickle.loads(request)

            # Check that request from client is a command request.
            if not request["type"] == "command":
                self.clientAlive = False
                break

            user = request["user"]
            data = request["data"]
            command_args = data["command_args"]

            # Commands.
            if data["command"] == "OUT":
                if self.handle_command_OUT(user, command_args):
                    self.clientAlive = False
            elif data["command"] == "BCM":
                self.handle_command_BCM(user, command_args)
            elif data["command"] == "ATU":
                self.handle_command_ATU(user, command_args)
            elif data["command"] == "SRB":
                self.handle_command_SRB(user, command_args)
            elif data["command"] == "SRM":
                self.handle_command_SRM(user, command_args)
            elif data["command"] == "RDM":
                self.handle_command_RDM(user, command_args)
            elif data["command"] == "UDP":
                self.handle_command_UDP(user, command_args)
            else:
                print("Unkown command")
                self.send_response("None", user, True, "Unknown command. Please try again\n", True)

    # ----------------------------------------------------------------
    # UDP command methods.
    # ----------------------------------------------------------------

    def handle_command_UDP(self, user, command_args):
        audience_username = command_args[0]

        audience_user = self.server_data.get_active_user_details(audience_username)
        self.send_response("UDP", user, True, audience_user, True)

    # ----------------------------------------------------------------
    # RDM command methods.
    # ----------------------------------------------------------------

    def handle_command_RDM(self, user, command_args):

        # Error Check: Incorrect number of arguments.
        if len(command_args) != 5:
            error_msg = "[ERROR] Usage: RDM <message-type> <timestamp>"
            self.send_response("RDM", user, False, error_msg, True)
            return

        message_type = command_args[0]
        day = command_args[1]
        month = command_args[2]
        year = command_args[3]
        time = command_args[4]

        timestamp = " ".join(command_args[1:])

        # Error Check: Timestamp is of the right syntax.
        try:
            input_datetime = self.create_datetime(day, month, year, time)
        except:
            error_msg = "[ERROR] Invalid timestamp syntax. Example use: '1 Jun 2001 15:30:00'"
            self.send_response("RDM", user, False, error_msg, True)
            return

        # Error Check: Valid message types.
        if not validate.validate_message_type(message_type):
            error_msg = "[ERROR] Invalid message type, must be 'b' or 's'"
            self.send_response("RDM", user, False, error_msg, True)
            return

        if message_type == "b":
            broadcast_messages = self.server_data.get_recent_broadcast_messages(input_datetime)
            if not broadcast_messages:
                message = f"No new broadcasted messages later than {timestamp}"
                self.send_response("RDM", user, True, message, True)
                return

            lines = f"Broadcasted messages after {timestamp}:\n"
            for bm in broadcast_messages:
                m_timestamp = self.convert_datetime_to_timestamp(bm["timestamp"])
                lines += f"       > ID: #{bm['message_id']}; {m_timestamp}; {bm['username']}; {bm['message']}\n"

            self.send_response("RDM", user, True, lines, True)
            
            # Print server output.
            print(f"> RDM Return Message for {user}:")
            print(textwrap.dedent(lines))

        elif message_type == "s":
            member_chat_rooms = self.server_data.get_chat_rooms_for_user(user)

            lines = ""

            for room in member_chat_rooms:
                room_messages = self.server_data.get_recent_chat_room_messages(input_datetime, room["room_id"])
            
                lines += f"\n    Room ID {room['room_id']}:\n"
                if not room_messages:
                    lines += f"\n    No new room messages after {timestamp}\n"

                for rm in room_messages:
                    m_timestamp = self.convert_datetime_to_timestamp(rm["timestamp"])
                    lines += f"       > ID: #{rm['message_id']}; {m_timestamp}; {rm['username']}; {rm['message']}\n"

            self.send_response("RDM", user, True, lines, True)

            # Print server output.
            print(f"> RDM Return Message for {user}:")
            print(textwrap.dedent(lines))


    def create_datetime(self, day, month, year, time):
        timestamp = f"{day} {month} {year} {time}"
        return datetime.strptime(timestamp, '%d %b %Y %X')

    
    # ----------------------------------------------------------------
    # SRM command methods.
    # ----------------------------------------------------------------

    def handle_command_SRM(self, user, command_args):
        error_msg = None
        if len(command_args) < 2:
            error_msg = "[ERROR] Usage: SRM <room-id> <message>"
        elif not validate.validate_room_id_digit(command_args[0]):
            error_msg = "[ERROR] Room ID must be a digit"
        elif not validate.validate_room_exists(self.server_data, int(command_args[0])):
            error_msg = "[ERROR] Room ID does not exist"
        elif not validate.validate_user_in_room(self.server_data, user, int(command_args[0])):
            error_msg = f"[ERROR] User is not in the room with ID: {int(command_args[0])}"
        
        # Send error if detected.
        if error_msg:
            self.send_response("SRM", user, False, error_msg, True)
            return

        room_id = int(command_args[0])
        message = " ".join(command_args[1:])
        
        # Generate chat room message id.
        message_id = self.server_data.generate_chat_room_message_id(room_id)

        # Create chat message.
        current_time = datetime.now()
        self.server_data.create_chat_room_message(room_id, user, message, message_id, current_time)

        # Send response.
        timestamp = self.convert_datetime_to_timestamp(current_time)
        data_text = f"Chat room message #{message_id} created in room {room_id} at {timestamp}"
        self.send_response("SRM", user, True, data_text, True)

        # Create message log.
        self.create_chat_room_message_log(user, message, message_id, timestamp, room_id)

        # pprint(self.server_data.get_chat_rooms())

        # Print server output.
        print(f"> SRM Return Message for {user}:")
        print(data_text)
        
    def create_chat_room_message_log(self, user, message, message_id, timestamp, room_id):
        with open(f"SR_{room_id}_messagelog.txt", "a") as stream:
            stream.write(f"{message_id}; {timestamp}; {user}; {message}\n")


    # ----------------------------------------------------------------
    # SRB command methods.
    # ----------------------------------------------------------------

    def handle_command_SRB(self, user, command_args):
        error_msg = None
        if not command_args:
            error_msg = "[ERROR] No usernames were supplied."
        
        # Send error if detected.
        if error_msg:
            self.send_response("SRB", user, False, error_msg, True)
            return

        members = command_args

        # User cannot create room with only themselves as a member.
        if len(members)  == 1 and user in members:
            data_text = f"User cannot create a room with only themselves"
            self.send_response(user, False, data_text, True)
            return

        # Check if a room already exists for these users.
        room_id = self.server_data.get_chat_room_id_by_users(members)
        if room_id:
            data_text = f"A separate room (ID: {room_id}) already created for these users"
            self.send_response("SRB", user, False, data_text, True)
            return

        # Check if any user is not registered.
        unknown_members = self.server_data.get_unknown_users(members)
        if unknown_members:
            data_text = f"Unknown Members: {', '.join(unknown_members)}"
            self.send_response("SRB", user, False, data_text, True)
            return
        
        inactive_members = self.server_data.get_inactive_users(members)
        if inactive_members:
            data_text = f"Inactive Members: {', '.join(inactive_members)}"
            self.send_response("SRB", user, False, data_text, True)
            return

        # Generate room id.
        room_id = self.server_data.generate_chat_room_id()

        # Create chat room.
        self.server_data.create_chat_room(room_id, members)

        # Send response.
        data_text = f"Separate chat room ({room_id}) created with: {', '.join(members)}"
        self.send_response("SRB", user, True, data_text, True)

        # Create chat room message log file.
        open(f"SR_{room_id}_messagelog.txt", "w").close()

        # pprint(self.server_data.get_chat_rooms())

        # Print server output.
        print(f"> SRB Return Message for {user}:")
        print(data_text)


    # ----------------------------------------------------------------
    # ATU command methods.
    # ----------------------------------------------------------------

    def handle_command_ATU(self, user, command_args):
        """Display active users to the client (excluding the user who 
        requested the command).

        Args:
            user (string)
            command_args (list of strings)
        """
        error_msg = None
        if command_args:
            error_msg = "[ERROR] ATU should have no arguments"

        # Send error if detected.
        if error_msg:
            self.send_response("ATU", user, False, error_msg, True)
            return

        # Grab other active users.
        download_active_users = []
        for active_user in self.server_data.get_active_users():
            if active_user["username"] != user:
                download_active_users.append(active_user)

        # If no other active users.
        if len(download_active_users) == 0:
            data_text = "No other active users"
            self.send_response("ATU", user, True, data_text, True)
            return

        # Send response.
        data_text = "Active users:\n"
        for active_user in download_active_users:
            name = active_user["username"]
            login_timestamp = active_user["login_timestamp"]
            IP_address = active_user["IP_address"]
            UDP_port = active_user["UDP_socket_port"]

            data_text += f"       > {name}, active since {login_timestamp}; IP: {IP_address}; UDP Port: {UDP_port}\n"
        
        self.send_response("ATU", user, True, data_text, True)

        # Print server output.
        print(f"> ATU Return Message for {user}:")
        print(textwrap.dedent(data_text))
    
    # ----------------------------------------------------------------
    # BCM command methods.
    # ----------------------------------------------------------------

    def handle_command_BCM(self, user, command_args):
        """Broadcast message to all users.

        Args:
            user (string)
            command_args (list of strings)
        """
        error_msg = None
        if not command_args:
            error_msg = "[ERROR] No message supplied"

        if error_msg:
            self.send_response("BCM", user, False, error_msg, True)
            return
        
        message = " ".join(command_args)

        # Generate message id.
        message_id = self.server_data.generate_broadcast_message_id()

        # Create broadcast message.
        current_time = datetime.now()
        self.server_data.create_broadcast_message(user, message, message_id, current_time)

        # Send response.
        timestamp = self.convert_datetime_to_timestamp(current_time)
        data_text = f"Broadcasted message #{message_id} at {timestamp}"
        self.send_response("BCM", user, True, data_text, True)

        # Create message log.
        self.create_message_log(user, message, message_id, current_time)

        # pprint(self.server_data.get_broadcast_messages())

        # Print server output.
        print(f"> BCM Return Message for {user}:")
        print(data_text)

    # ----------------------------------------------------------------
    # OUT command methods.
    # ----------------------------------------------------------------

    def handle_command_OUT(self, user, command_args):
        """Logout the given active user themself.

        Args:
            user (string)
            command_args (list of strings)

        Returns:
            boolean: Logout status.
        """
        error_msg = None
        if command_args:
            error_msg = "[ERROR] OUT should have no arguments"

        # Send error if detected.
        if error_msg:
            self.send_response("OUT", user, False, error_msg, True)
            return False

        # Delete active user and active user log.
        self.server_data.delete_active_user(user)
        self.delete_user_log(user)

        # Send response.
        
        data_text = f"{user} has successfully logged out"
        self.send_response("OUT", user, True, data_text, False)

        # Print to server output.
        print(f"{user} has logged out")

        return True

    # ----------------------------------------------------------------
    # Response methods.
    # ----------------------------------------------------------------

    def send_response(self, command, user, status, data, keep_alive):
        response = {
            "command": command,
            "user": user,
            "status": status,
            "data": data,
            "keep_alive": keep_alive,
        }
        self.clientSocket.sendall(pickle.dumps(response))

    # ----------------------------------------------------------------
    # Authentification methods.
    # ----------------------------------------------------------------

    def authenticate_client(self):
        # Send login request.
        input_login_attempts = int(sys.argv[2])
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

    def delete_user_log(self, user):
        with open("userlog.txt", "r") as stream:
            lines = stream.readlines()

        # Remove the relevant user.
        removed_line = ""
        for line in lines:
            log_line = re.split(r"; ", line)
            log_username = log_line[2]
            if log_username == user:
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

    def create_message_log(self, user, message, message_id, timestamp):
        timestamp = self.convert_datetime_to_timestamp(timestamp)

        with open("messagelog.txt", "a") as stream:
            stream.write(f"{message_id}; {timestamp}; {user}; {message}\n")

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
    serverSocket.bind((HOST, server_port))
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
    if len(sys.argv) != 3:
        print("Usage: python3 server.py <server-port> <login-attempts>")
        sys.exit(1)

    # Check login_attempts is of type int.
    if not validate.validate_login_attempts_number(sys.argv[2]):
        print("<login-attempts> must be a number between 1 and 5")
        sys.exit(1)

    server_port = int(sys.argv[1])

    # Start server.
    start()

