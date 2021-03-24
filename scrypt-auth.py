from passlib.hash import scrypt
from sys import exit as callexit
import sqlite3

"""
    Autentica o usuário especificado em uma base
    sqlite3 utilizando scrypt.

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

db = "db1.sqlite3"
conn = sqlite3.connect(db)
cc = conn.cursor()
select_username = "SELECT * FROM scrypt where username =?"

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
                    hashed_db_password = check_users[1]
                    checkpwd = scrypt.verify(password, hashed_db_password)
                    
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
