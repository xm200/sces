from flask import Flask, request
from Crypto.Util import number
import uuid
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


@app.route("/api/create_package", methods=["POST"])
def create_package():
    global used_packages_uuid
    parameters = ['weight', 'width', 'height', 'thickness']
    
    for param in parameters:
        if param not in request.args.keys():
            return "Bad request", 400
        
    while (package_uuid := uuid.uuid1()) in used_packages_uuid:
        continue
    
    used_packages_uuid.add(package_uuid)

    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    cursor.execute("INSERT INTO packages VALUES(?, ?, ?, ?, ?)", (package_uuid, float(request.weight), int(request.width), int(request.height), int(request.thickness)))
    con.commit()
    con.close()

    return f"Package created, uid: {package_uuid}", 200
    


@app.route("/api/remove_package")
def remove_package():
    if request.uid is None:
        return "Bad request"
    
    global used_packages_uuid

    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    cursor.execute("DELETE FROM packages WHERE id=?", (request.uid, )).fetchone()
    con.commit()

    used_packages_uuid.pop(request.uid)

    return "Package deleted", 200



used_packages_uuid = set()

@app.route("/")
def main():
    return "It works!"

os.environ['Q_MODULO_PART'] = str(number.getPrime(1024))
os.environ['P_MODULO_PART'] = str(number.getPrime(1024))

if not os.path.isfile('./db'):
    os.mkdir("./db")

if not os.path.isfile('./db/users.db'):
    open("./db/users.db", "a").close()
    con = sqlite3.connect("./db/users.db")
    cursor = con.cursor()
    cursor.execute("CREATE TABLE users(uid, pubkey, privkey)")
    con.close()

if not os.path.isfile('./db/packages.db'):
    open('./db/packages.db', 'a').close()
    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    cursor.execute("CREATE TABLE packages(id, weight, width, height, thinkness)")
    con.close()

if not os.path.isfile("./db/pairs.db"):
    open('./db/pairs.db', 'a').close()
    con = sqlite3.connect("./db/pairs.db")
    cursor = con.cursor()
    cursor.execute("CREATE TABLE pairs(hash, pdata)")
    con.close()

if __name__ == "__main__":
    app.run("localhost", 8888)
