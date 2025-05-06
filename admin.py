import requests
import hashlib
import sqlite3

def set_user(pdata: str, addr: str, port):
    r = requests.get(f"http://{addr}:{port}/api/set_user?pdata={pdata}")
    hash = hashlib.sha256(pdata.encode()).hexdigest()
    print(f"Personal data hash: {hash}", f"Public key: {r.text}", sep='\n')

    con = sqlite3.connect("./db/pairs.db")
    cursor = con.cursor()
    cursor.execute("INSERT INTO pairs VALUES(?, ?)", (hash, pdata))
    con.commit()
    con.close()

