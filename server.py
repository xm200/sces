from flask import Flask, request
import sympy
import sqlite3
import os
import hashlib

app = Flask("Server SCES")

def extended_gcd(e: int, d: int):
    if e == 0: return d, 0, 1
    gcd, s, t = extended_gcd(d % e, e)
    return gcd, t - (d // e) * s, s


def gen_rsa_pkey():
    p, q = 17, 65537 # p, q = os.getenv("P_MODULO_PART"), os.getenv("Q_MODULO_PART")
    fi = (p - 1) * (q - 1)
    e = sympy.randprime(128, 256)
    d = extended_gcd(e, fi)[1]
    return e, d


@app.route("/api/check_user", methods=["GET"])
def check_user():
    # server has private key to verify signature
    # signature is encrypted hash of surname
    sign = request.args.get('sign') # get public signature
    uid = request.args.get("uid") # from which user server need to get private key to check signature
    if sign is None or uid is None:
        return "Bad request!", 400
    try:
        con = sqlite3.connect("./db/users.db")
    except Exception as e:
        return "Bad request!", 400

    cursor = con.cursor()
    try:
        privkey = cursor.execute("SELECT privkey FROM users WHERE uid=?", (uid, ))
    except Exception as e:
        con.close()
        return "Bad request!", 400
    
    p, q = os.getenv("P_MODULO_PART"), os.getenv("Q_MODULO_PART")
    con.close()

    if pow(sign, privkey, p * q) == uid:
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

    cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (hash, e, d))

    con.close()
    return str(e), 200
    


@app.route("/")
def main():
    return "It works!"


if not os.path.isfile('./db/users.db'):
    os.mkdir("./db")
    open("./db/users.db", "a").close()
    con = sqlite3.connect("./db/users.db")
    cursor = con.cursor()
    cursor.execute("CREATE TABLE users(uid, pubkey, privkey)")
    con.close()    

if __name__ == "__main__":
    app.run("localhost", 8888)