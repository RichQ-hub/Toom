
import re

def validate_login_attempts_number(login_attempts):
    if login_attempts.isnumeric():
        if int(login_attempts) >= 1 and int(login_attempts) <= 5:
            return True
    return False

def validate_chat_room_members_exist(server_data, usernames):
    chat_rooms = server_data.get_chat_rooms()
    for room in chat_rooms:
        if set(room["members"]) == set(usernames):
            return True
    return False

def validate_room_id_digit(room_id):
    if re.fullmatch(r"\d+", room_id):
        return True
    return False

def validate_user_in_room(server_data, user, room_id):
    room = server_data.get_chat_room_details(room_id)
    if user in room["members"]:
        return True
    return False

def validate_room_exists(server_data, room_id):
    chat_rooms_ids_list = server_data.get_chat_room_ids()
    if room_id in chat_rooms_ids_list:
        return True
    return False

def validate_message_type(message_type):
    if message_type == 'b' or message_type == 's':
        return True
    return False
