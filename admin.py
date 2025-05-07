import requests
import hashlib
import sqlite3


banner = '''Hello! it is console admin UI
Main commands:
- set user (enter personal data)
- get user (enter personal data)
- get package (enter packages uuid)
- exit UI
'''


def set_user(pdata: str, addr: str, port: str):
    r = requests.get(f"http://{addr}:{port}/api/set_user?pdata={pdata}")
    hash = hashlib.sha256(pdata.encode()).hexdigest()

    con = sqlite3.connect("./db/pairs.db")
    cursor = con.cursor()
    cursor.execute("INSERT INTO pairs VALUES(?, ?)", (hash, pdata))
    con.commit()
    con.close()

    return f"Personal data hash: {hash}", f"Public key: {r.text}"


def get_user(pdata: str):
    con = sqlite3.connect("./db/pairs.db")
    data = con.cursor().execute("SELECT * FROM pairs WHERE pdata=?", (pdata, )).fetchone()
    con.close()
    return data


def get_package(uid: str):
    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    package = cursor.execute("SELECT * FROM packages WHERE uid=?", (uid, )).fetchall()
    con.close()
    return package


def main():
    print(banner)
    while (cmd := input("> ").split()) != "exit":
        if cmd[0] == "set":
            print(set_user(cmd[-1], "localhost", "8888"))
        elif cmd[0] == 'get':
            if cmd[1] == "package":
                print(get_package(input("uid > ")))
            elif cmd[1] == "user":
                print(get_user(input("personal data > ")))
        else:
            print("Unknown command!")


if __name__ == "__main__":
    main()

