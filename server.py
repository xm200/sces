from flask import Flask, request
from Crypto.Util import number
import sqlite3
import os
import hashlib

app = Flask("Server SCES")

def gen_rsa_pkey():
    p, q = int(os.getenv("P_MODULO_PART")), int(os.getenv("Q_MODULO_PART"))
    phi = (p - 1) * (q - 1)
    e = number.getPrime(256)
    d = pow(e, -1, phi)
    return e, d


@app.route("/api/check_user", methods=["GET"])
def check_user():
    # server has private key to verify signature
    # signature is encrypted hash of surname
    pubkey = int(request.args.get('pubkey')) # get public key
    uid = request.args.get("uid") # from which user server need to get private key to check signature
    if pubkey is None or uid is None:
        return "Bad request!", 400
    try:
        con = sqlite3.connect("./db/users.db")
    except Exception:
        return "Bad request!", 400

    cursor = con.cursor()
    try:
        privkey = int(cursor.execute("SELECT privkey FROM users WHERE uid=?", (uid, )).fetchone()[0])
    except Exception:
        con.close()
        return "Bad request!", 400
    
    p, q = int(os.getenv("P_MODULO_PART")), int(os.getenv("Q_MODULO_PART"))
    n = p * q
    con.close()

    if pow(pow(int(uid, 16), pubkey, n), privkey, n) == int(uid, 16):
        return "Ok", 200

    return "Bad request!", 400


@app.route("/api/set_user", methods=["POST"])
def set_user():
    data = request.args.get("pdata")
    if data is None:
        return "Bad request", 400
    
    hash = hashlib.sha256(data.encode()).hexdigest()
    e, d = gen_rsa_pkey()

    con = sqlite3.connect("./db/users.db")
    cursor = con.cursor()

    cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (hash, str(e), str(d)))
    con.commit()
    con.close()
    return str(e), 200
    


@app.route("/")
def main():
    return "It works!"

os.environ['Q_MODULO_PART'] = str(number.getPrime(1024))
os.environ['P_MODULO_PART'] = str(number.getPrime(1024))

if not os.path.isfile('./db/users.db'):
    os.mkdir("./db")
    open("./db/users.db", "a").close()
    con = sqlite3.connect("./db/users.db")
    cursor = con.cursor()
    cursor.execute("CREATE TABLE users(uid, pubkey, privkey)")
    con.close()    

if __name__ == "__main__":
    app.run("localhost", 8888)

# "GET /api/check_user?pubkey=108824157194683190612366456491022126664658596708153474417138779042824141100327&uid=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 HTTP/1.1" 
