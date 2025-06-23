def generate_cmd_payloads():
    return [
        "; ls",
        "&& whoami",
        "| id",
        "& net user",
        "`uname -a`"
    ]
