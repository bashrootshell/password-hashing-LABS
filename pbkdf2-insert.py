from hashlib import pbkdf2_hmac
from secrets import token_bytes
from time import time
import sqlite3

"""
    Cadastra o usuário especificado em uma base
    sqlite3 utilizando pbkdf2.

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

# dict_users = {}

print(f'--- Criação das credencias de novo usuário ---')
print(f'Digite um nome de usuário:')
username = input()
if len(username) == 0:
    print(f'Digite um nome de usuário.')
    exit()
else:
    conn = sqlite3.connect("dbusers.pbkdf2.sqlite3")
    cc = conn.cursor()
    cc.execute("SELECT * FROM users where username =?", (username,))
    data = cc.fetchone()
    if data is not None:
        print(f'Usuário já cadastrado.')
        conn.close()
        exit()
    else:
        pass
print(f'Digite a senha para o usuário {username}\n'
      f' Use ao menos 2 dígitos e 2 caracteres em caixa alta.')
password1 = input()

nb = sum([1 for ch in password1 if ch.isdigit()])
upp = sum([1 for ch in password1 if ch.isupper()])

if nb < 2 or upp < 2 or len(password1) < 10:
    print(f'É preciso digitar uma senha igual ou maior que 10 caracteres'
          f' e utilizando ao menos 2 dígitos e 2 caracteres em caixa alta.')
    exit()
else:
    print(f'Digite novamente a senha para o usuário {username}:')
    password2 = input()
    if len(password2) < 10:
        print(f'É preciso digitar uma senha igual ou maior que 10 caracteres.')
        exit()

    if password2 == password1:
        salt = token_bytes(64)
        hashedpwd = pbkdf2_hmac('sha3_512', salt,
                                password1.encode('utf-8'), 25000)

        '''dict_users[username] = {'salt': salt, 'hashedpwd': hashedpwd}
        salt = dict_users[username]['salt']
        hashedpwd = dict_users[username]['hashedpwd']'''

        try:
            print('Conectando no banco de dados...')
            conn = sqlite3.connect("dbusers.sqllite.db")
            cc = conn.cursor()
            unixtime = int(time())
            cc.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                       (username, salt, hashedpwd, unixtime))
            conn.commit()
            print(f'Usuário "{username}" cadastrado com sucesso.')
            conn.close()

        except sqlite3.Error as erro:
            print(f'Erro: {erro}')

    else:
        print('Senhas não conferem. Tente novamente.')
