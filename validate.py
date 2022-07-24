
def validate_login_attempts_number(login_attempts):
    if login_attempts.isnumeric():
        if int(login_attempts) >= 1 and int(login_attempts) <= 5:
            return True
    return False

def validate_no_command_args(command_args):
    if len(command_args) == 0:
        return True
    return False
