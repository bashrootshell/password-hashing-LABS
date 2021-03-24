from passlib.hash import pbkdf2_sha512
from time import time
import sqlite3

"""
    Cadastra o usuário especificado em uma base
    sqlite3 utilizando pbkdf2 (passlib.hash module).

    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

db = "db1.sqlite3"
conn = sqlite3.connect(db)
cc = conn.cursor()
select_username = "SELECT * FROM pbkdf2passlib where username =?"
insert_username = "INSERT INTO pbkdf2passlib VALUES (?, ?, ?)"

print('--- Criação das credencias de novo usuário ---\n\
    Digite um nome de usuário:')
username = input()

if len(username) == 0:
    print('Digite um nome de usuário.')
else:
    cc.execute(select_username, (username,))
    check_users = cc.fetchone()
    if check_users is not None:
        print('Usuário já cadastrado.')
        conn.close()
    else:
        pass

print(f'Digite a senha para o usuário {username}\n'
      f' Use ao menos 2 dígitos e 2 caracteres em caixa alta.')
password1 = input()

num_digits = sum([1 for ch in password1 if ch.isdigit()])
num_upper = sum([1 for ch in password1 if ch.isupper()])

if num_digits < 2 or num_upper < 2 or len(password1) < 10:
    print('É preciso digitar uma senha igual ou maior que 10 caracteres'
          ' e utilizando ao menos 2 dígitos e 2 caracteres em caixa alta.')
else:
    print(f'Digite novamente a senha para o usuário {username}:')
    password2 = input()
    if len(password2) < 10:
        print('É preciso digitar uma senha igual ou maior que 10 caracteres.')
    if password2 == password1:
        hashedpwd = pbkdf2_sha512.using(salt_size=64).hash(password1)

        try:
            print('Conectando ao banco de dados...')
            unixtime = int(time())
            cc.execute(insert_username, (username, hashedpwd, unixtime))
            conn.commit()
            print(f'Usuário "{username}" cadastrado com sucesso.')
            conn.close()

        except sqlite3.Error as erro:
            print(f'Erro: {erro}')

    else:
        print('Senhas não conferem. Tente novamente.')
