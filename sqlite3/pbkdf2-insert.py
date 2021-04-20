from passlib.hash import pbkdf2_sha512
from time import time
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
insert_username = "INSERT INTO pbkdf2passlib VALUES (?, ?, ?)"


def check_if_username_exists():
    global username
    print('--- Credentials System ---\n\
    Please type the user name:')
    username = input()
    assert username, 'Please type the user name.'
    cc.execute(select_username, (username,))
    assert cc.fetchone() is None, f'User {username} already in the database.'
    return username


def check_the_quality_of_the_password():
    global password
    print(f'Please type a password for {username}\n'
          f' 10+ chars, with 2 digits and 2 uppercase letters.')
    password = input()
    num_digits = sum([1 for chars in password if chars.isdigit()])
    num_upper = sum([1 for chars in password if chars.isupper()])
    assert num_digits >= 2 and num_upper >= 2 and len(password) >= 10, (
        'Please type a password with 10+ chars, with 2 digits'
        ' and 2 uppercase letters.')
    return password


def insert_username_into_database():
    try:

        hashedpwd = pbkdf2_sha512.using(salt_size=64).hash(password)
        print('Connecting with the database...')
        unixtime = int(time())
        cc.execute(insert_username, (username, hashedpwd, unixtime))
        conn.commit()
        print(f'User {username} successfully inserted.')
        conn.close()

    except conn.Error as error:
        print(f'Error: {error}')


check_if_username_exists()
check_the_quality_of_the_password()
insert_username_into_database()
