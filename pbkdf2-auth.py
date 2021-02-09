from hashlib import pbkdf2_hmac
from secrets import token_bytes
import sqlite3

"""
    Autentica o usuário especificado em uma base
    sqlite3 utilizando pbkdf2.

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

try:

    print(f'Autenticação de usuário.')
    print(f'Digite um nome de usuário:')
    user = input()
    if len(user) == 0:
        print(f'Erro: Digite um nome de usuário.')
        exit()
    else:
        conn = sqlite3.connect("dbusers.pbkdf2.sqllite3")
        cc = conn.cursor()
        cc.execute("SELECT * FROM users where username =?", (user,))
        data = cc.fetchall()
        if data != []:
            for row in data:
                print(f'Digite a senha para o usuário {user}:')
                password = input()
                if len(password) == 0:
                    print(f'É preciso digitar uma senha. Inicie novamente.')
                    conn.close()
                    exit()
                else:
                    salt = row[1]
                    hashed_db_password = row[2]
                    checkpwd = pbkdf2_hmac('sha3_512', salt,
                                           password.encode('utf-8'), 25000)
                    if checkpwd == hashed_db_password:
                        print(f'Usuário "{user}" está autenticado.')
                        conn.close()
                        exit()
                    else:
                        print(f'Senha inválida para o usuário "{user}".')
                        conn.close()
                        exit()
        else:
            print(f'Usuário {user} não encontrado.')
            conn.close()
            exit()

except sqlite3.Error as erro:
    print(f'Erro: {erro}')
