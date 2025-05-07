import requests
import hashlib

def check_user(pdata: str, addr: str, port: int, pubkey: int):
    r = requests.get(f"http://{addr}:{port}/api/check_user?uid={hashlib.sha256(pdata.encode()).hexdigest()}&pubkey={pubkey}")

    if r.text != "Ok":
        return "Invalid user"
    else:
        return "valid user"


def get_package(uid: str, addr: str, port: int):
    return requests.get(f"http://{addr}:{port}/api/check_package?uid={uid}").text

banner = """Hello! It is client UI
Main commands:
- check user (enter its personal data and its pubkey)
- get package (enter package uid)
- exit UI
"""

def main():
    print(banner)
    while (cmd := input("> ").split()[0]) != "exit":
        if cmd[0] == "check":
            params1 = input("personal data and public key > ").split()
            print(check_user(params1[0], "localhost", "8888", params1[1]))
        elif cmd[0] == "get":
            print(get_package(input("package uid > "), "localhost", "8888"))
        else:
            print("Invalid command")

if __name__ == "__main__":
    main()
