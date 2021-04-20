from passlib.hash import pbkdf2_sha512
from sys import exit as callexit
from sqlite3 import connect

"""
    PEP8 compliant
    “Beautiful is better than ugly.”
    — The Zen of Python
"""

db = "db1.sqlite3"
conn = connect(db)
cc = conn.cursor()
select_username = "SELECT * FROM pbkdf2passlib where username =?"


def auth_username():

    print('User Authentication.\nPlease type the user name:')
    username = input()
    assert username, 'Please type the user name.'

    try:

        cc.execute(select_username, (username,))
        data_returned = cc.fetchone()
        assert data_returned is not None, 'User not found.'
        for _ in data_returned:
            print(f'Please type the password for {username}:')
            password = input()
            assert password, 'Please type a password'
            hashed_db_password = data_returned[1]
            checkpwd = pbkdf2_sha512.verify(password, hashed_db_password)
            if checkpwd:
                print(f'The user "{username}" has been authenticated.')
                conn.close()
                callexit()
            else:
                print(f'Invalid password for "{username}".')
                conn.close()
                callexit()

    except conn.Error as error:
        print(f'Error: {error}')


auth_username()
