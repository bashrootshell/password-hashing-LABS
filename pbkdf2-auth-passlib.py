from passlib.hash import pbkdf2_sha512
from sys import exit as callexit
import sqlite3

"""
    Autentica o usuário especificado em uma base
    sqlite3 utilizando pbkdf2 (passlib.hash module).

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

db = "db1.sqlite3"
conn = sqlite3.connect(db)
cc = conn.cursor()
select_username = "SELECT * FROM pbkdf2passlib where username =?"

try:

    print('Autenticação de usuário.\nDigite um nome de usuário:')
    user = input()
    
    if len(user) == 0:
        print('Erro: Digite um nome de usuário.')
    else:
        cc.execute(select_username, (user,))
        check_users = cc.fetchone()
        if check_users is not None:
            for _ in check_users:
                print(f'Digite a senha para o usuário {user}:')
                password = input()
                
                if len(password) == 0:
                    print('É preciso digitar uma senha. Inicie novamente.')
                    conn.close()
                    callexit()
                else:
                    salt = check_users[1]
                    hashed_db_password = check_users[1]
                    checkpwd = pbkdf2_sha512.verify(password,
                                                    hashed_db_password)
                    
                    if checkpwd:
                        print(f'Usuário "{user}" está autenticado.')
                        conn.close()
                        callexit()
                    else:
                        print(f'Senha inválida para o usuário "{user}".')
                        conn.close()
                        callexit()
        else:
            print(f'Usuário {user} não encontrado.')
            conn.close()

except sqlite3.Error as erro:
    print(f'Erro: {erro}')
