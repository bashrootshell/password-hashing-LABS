from passlib.hash import argon2
from time import time
import sqlite3

"""
    Cadastra o usuário especificado em uma base
    sqlite3 utilizando argon2.

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

db = "db1.sqlite3"
conn = sqlite3.connect(db)
cc = conn.cursor()
select_usuario = "SELECT * FROM argon2 where username =?"
insert_usuario = "INSERT INTO argon2 VALUES (?, ?, ?)"

print('--- Criação das credencias de novo usuário ---\n\
    Digite um nome de usuário:')
usuario = input()
if len(usuario) == 0:
    print('Digite um nome de usuário.')
else:
    cc.execute(select_usuario, (usuario,))
    check_users = cc.fetchone()
    if check_users is not None:
        conn.close()
        print('Usuário já cadastrado.')

print(f'Digite a senha para o usuário {usuario}\n'
      f' Use ao menos 2 dígitos e 2 caracteres em caixa alta.')
pass_check_1 = input()

num_digits = sum([1 for chars in pass_check_1 if chars.isdigit()])
num_upper = sum([1 for chars in pass_check_1 if chars.isupper()])

if num_digits < 2 or num_upper < 2 or len(pass_check_1) < 10:
    print('É preciso digitar uma senha igual ou maior que 10 caracteres'
          ' e utilizando ao menos 2 dígitos e 2 caracteres em caixa alta.')
else:
    print(f'Digite novamente a senha para o usuário {usuario}:')
    pass_check_2 = input()
    if len(pass_check_2) < 10:
        print('É preciso digitar uma senha igual ou maior que 10 caracteres.')

    if pass_check_2 == pass_check_1:
        hashedpwd = argon2.using(salt_size=64).hash(pass_check_1)
        try:
            print('Conectando ao banco de dados...')
            unixtime = int(time())
            cc.execute(insert_usuario, (usuario, hashedpwd, unixtime))
            conn.commit()
            print(f'Usuário "{usuario}" cadastrado com sucesso.')
            conn.close()

        except sqlite3.Error as erro:
            print(f'Erro: {erro}')

    else:
        print('Senhas não conferem. Tente novamente.')
