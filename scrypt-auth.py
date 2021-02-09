from passlib.hash import scrypt
import sqlite3

"""
    Autentica o usuário especificado em uma base
    sqlite3 utilizando scrypt.

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
        conn = sqlite3.connect("dbusers.scrypt.sqlite3")
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
                    hashed_db_password = row[1]
                    checkpwd = scrypt.verify(password, hashed_db_password)
                    if checkpwd:
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
