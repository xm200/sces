from flask import Flask, request
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
# from flask_sslify import SSLify # Добавить при переносе в Docker
import binascii
import pbkdf2
import base64
import json
import uuid
import sqlite3
import os
import hashlib

app = Flask("Server SCES")
# sslify = SSLify(app) Добавить при переносе в Docker
# Генерация случайного симметричного ключа шифрования для выдачи API токенов
# Токен - JSON с правами и некими персональными данными для аутентификации, зашифрованный этим ключом.
# Токен кодируется в base64 для возможности копирования

SEED = 'EXAMPLE_KEY_SEED' # ИЗМЕНИТЕ ПРИ ЭКСПЛУАТАЦИИ
SALT = os.urandom(16)
iv = b"0123456789101112" # ИЗМЕНИТЕ ПРИ ЭКСПЛУАТАЦИИ

key = get_random_bytes(16)
hexed_key = binascii.hexlify(key)

os.environ['SECRET_KEY'] = binascii.hexlify(key).decode()
print(hexed_key, len(hexed_key)) # На всякий случай


# Это алгоритм генерации пары ключей RSA
def gen_rsa_pkey():
    p, q = int(os.getenv("P_MODULO_PART")), int(os.getenv("Q_MODULO_PART")) # p, q - простые части модуля, хранятся в переменных окружения
    phi = (p - 1) * (q - 1) # Вычисление функции Эйлера
    e = number.getPrime(256) # Конечно, важно лишь условие об НОД(e, phi) = 1, но, в простых числах жто выполняется
    d = pow(e, -1, phi) # Поиск обратного по модулю числа
    return e, d


# Это общедоступная страничка
# Нужна для проверки подлинности подписей
# У сервера есть приватный ключ для проверки подписи
# Подпись - это хеш персональных данных
@app.route("/api/check_user", methods=["GET"])
def check_user():
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


@app.route("/register", methods=['GET', 'POST'])
def register():
    pass


def decrypt_session(session: str):
    global iv
    cipher = AES.new(binascii.unhexlify(os.environ['SECRET_KEY']), AES.MODE_CBC, iv)
    decoded = base64.b64decode(session)
    decrypted = cipher.decrypt(decoded)
    return decrypted


@app.route("/get_token", methods=['GET'])
def get_token():
    if 'username' not in request.args.keys() or 'password' not in request.args.keys():
        return "Bad request", 400
    
    db = ["packages", "users", "all_users", "pairs"]
    auth = False

    # for i in db:
    #     con = sqlite3.connect(f"./db/{i}.db")
    #     cursor = con.cursor()
    #     session = {}
    #     data = cursor.execute(f"SELECT * FROM {i} WHERE login=? AND pass=?", (request.args.get('login'), request.args.get('pass'))).fetchall()
    #     if len(data) > 0:
    #         session['role'] = data[-1]
    #         session['name'] = data[0]
    #         session['pass'] = data[2]
    #         auth = True
    #         break

    # if not auth:
        # return "Not a user!", 403
    global iv
    session = {}
    session['role'] = request.args.get('u')
    session['name'] = request.args.get('username')
    session['pass'] = request.args.get('password')

    cipher = AES.new(binascii.unhexlify(os.environ['SECRET_KEY']), AES.MODE_CBC, iv)

    test = cipher.encrypt(bytes(pad(json.dumps(session).encode(), cipher.block_size)))
    return f"Your session: {base64.b64encode(test)}, decrypted_version: {decrypt_session(base64.b64encode(test))}"
    




# Это страничка для администраторов
# На ней создаются пользователи
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

    con = sqlite3.connect("./db/pairs.db")
    cursor = con.cursor()

    cursor.execute("INSERT INTO pairs VALUES (?, ?)", (hash, data))
    con.commit()
    con.close()

    return str(e), 200


@app.route("/api/checkpoint", methods=['POST', 'GET'])
def checkpoint():
    pass


# Это страница для админов, менеджеров, продавцов
# Здесь создвются посылки
@app.route("/api/create_package", methods=["POST"]) 
def create_package(): # todo: Сделать контроль целостности засчёт сохранения фоток и видео
    parameters = ['weight', 'width', 'height', 'thickness']
    
    for param in parameters:
        if param not in request.args.keys():
            return "Bad request", 400
        
    package_uuid = uuid.uuid1()

    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    cursor.execute("INSERT INTO packages (id, weight, width, height, thinkness, approve_path) VALUES (?, ?, ?, ?, ?)", (str(package_uuid), float(request.args.get('weight')), int(request.args.get('width')), int(request.args.get('height')), int(request.args.get('thickness'))))
    con.commit()
    con.close()

    os.mkdir("./packages/" + str(package_uuid))

    return f"Package created, uid: {package_uuid}", 200
    

# Страничка для загрузки файлов
# Доступна для сотрудников
@app.route("/approve_files")
def approve_files():
    pass # todo: approve HTML, подумать на тему сохранения данных и файлов по uuid


@app.route("/api/check_package", methods=['GET'])
def check_package():
    if 'uid' not in request.args.keys():
        return "Bad request", 400
    
    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    r = cursor.execute("SELECT * FROM packages WHERE id=?", (request.args.get('uid'), )).fetchall()
    con.close()
    return r

# Страничка служебная, для удаления посылок.
# Когда посылка доставлена, она удаляется из всех бд.
@app.route("/api/remove_package")
def remove_package():
    if 'uid' not in request.args.keys():
        return "Bad request", 400

    con = sqlite3.connect("./db/packages.db")
    cursor = con.cursor()
    cursor.execute("DELETE FROM packages WHERE id=?", (str(request.args.get('uid')), )).fetchone()
    con.commit()

    return "Package deleted", 200


# Это страничка для админов.
# Репорты - специальная жалоба сотрудника, если что-то пошло не так при передаче посылки
@app.route("/reports")
def reports():
    pass # todo: придумать и написать сохранение репортов


@app.route("/")
def main():
    return "It works!"


os.environ['Q_MODULO_PART'] = str(number.getPrime(1024))
os.environ['P_MODULO_PART'] = str(number.getPrime(1024))

if not os.path.isdir('./db'):
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

if not os.path.isfile('./db/all_users.db'):
    open("./db/all_users.db", "a").close()
    con = sqlite3.connect("./db/all_users.db")
    cursor = con.cursor()
    cursor.execute("CREATE TABLE all_users(name, password)")
    con.close()

if not os.path.isdir("./packages"):
    os.mkdir("./packages")

if __name__ == "__main__":
    app.run("localhost", 8888)
