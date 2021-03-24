from passlib.hash import argon2
from sys import exit as callexit
import sqlite3

"""
    Autentica o usuário especificado em uma base
    sqlite3 utilizando argon2.

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

db = "db1.sqlite3"
select_username = "SELECT * FROM argon2 where username =?"

try:

    print('Autenticação de usuário.\nDigite um nome de usuário:')
    user = input()
    if len(user) == 0:
        print('Erro: Digite um nome de usuário.')
    else:
        conn = sqlite3.connect(db)
        cc = conn.cursor()
        cc.execute(select_username, (user,))
        retorno_consulta = cc.fetchone()
        if retorno_consulta is not None:
            for _ in retorno_consulta:
                print(f'Digite a senha para o usuário {user}:')
                password = input()
                if len(password) == 0:
                    print('É preciso digitar uma senha. Inicie novamente.')
                    conn.close()
                    callexit()
                else:
                    hashed_db_password = retorno_consulta[1]
                    checkpwd = argon2.verify(password, hashed_db_password)
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
