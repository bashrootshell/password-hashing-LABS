#!/usr/bin/env python3

from cloudant.client import CouchDB
from passlib.hash import argon2
from stdiomask import getpass
from string import punctuation
from datetime import datetime
from simple_term_menu import TerminalMenu


DBADMIN = 'admin'
SENHADB = 'admin'
URL_COUCH = 'http://127.0.0.1:5984'
CONEXAO = CouchDB(DBADMIN, SENHADB, url=URL_COUCH, connect=True)
BANCODB = CONEXAO['db_auth']
POLITICA_SENHA_VALIDA = ('Digite uma senha com 10+ caracteres, 2 dígitos '
                         'e 2 caracteres em caixa alta.')


def checa_se_usuario_existe():

    global usuario
    usuario = input('> ')
    if len(usuario) == 0:
        exit('Digite um nome de usuário')
    elif usuario in BANCODB:
        return True
        return usuario
    else:
        return False
        return usuario


def verifica_senha():

    global doc, senha
    doc = BANCODB[usuario]
    print(f'Digite a senha para o usuário {usuario}')
    senha = getpass('Senha: ')
    hashpwd = doc['senha']
    if argon2.verify(senha, hashpwd):
        return True
        return doc, senha
    else:
        return False


def checa_qualidade_da_senha():

    global novasenha
    novasenha = getpass('Senha: ')
    TAMANHO = len(novasenha)
    DEC = sum([1 for char in novasenha if char.isdecimal()])
    UPPER = sum([1 for char in novasenha if char.isupper()])
    LOWER = sum([1 for char in novasenha if char.islower()])
    SPACE = sum([1 for char in novasenha if char.isspace()])
    PUC = sum([1 for char in novasenha if char in punctuation])
    [POLITICA_DE_SENHA := TAMANHO >= 2 and DEC >= 1 and UPPER >= 1]
    if POLITICA_DE_SENHA:
        return True
        return novasenha
    else:
        return False


def cadastra_usuario_no_banco():

    print('--- Criação das credencias de novo usuário ---\n\
    Digite um nome de usuário:')
    usuario_existe = checa_se_usuario_existe()
    if usuario_existe is None:
        print('Digite um nome de usuário.')
    elif usuario_existe is True:
        print('Usuário já existe na base')
    elif usuario_existe is False:
        if checa_qualidade_da_senha() is False:
            print(POLITICA_SENHA_VALIDA)
        else:
            hashedpwd = argon2.using(rounds=8, salt_size=128).hash(novasenha)
            data = datetime.now().strftime("%d/%m/%Y %H:%M:%S UTC−03:00")
            credenciais = {'_id': usuario,
                           'nome': usuario,
                           'senha': hashedpwd,
                           'data_criacao': data,
                           'alteracoes_senha': 0}
            cadastro = BANCODB.create_document(credenciais)
            if usuario in BANCODB:
                print(f'Usuário {usuario} criado com sucesso.')


def autentica_usuario():

    print('--- Autenticação de usuário ---\n\
        Digite um nome de usuário:')
    if checa_se_usuario_existe() is False:
        exit('Usuário não existe na base')
    if verifica_senha():
        print(f'Usuário "{usuario}" está autenticado.')
    else:
        print(f'Senha inválida para o usuário "{usuario}".')


def altera_senha_de_usuario():

    print('--- Alteração das credencias usuário ---\n\
    Digite um nome de usuário:')
    if checa_se_usuario_existe() is False:
        exit('Usuário não existe na base')
    if verifica_senha():
        senha_antiga = senha  # retorno > "verifica_senha"
        print(POLITICA_SENHA_VALIDA)
        if checa_qualidade_da_senha() is False:
            print(POLITICA_SENHA_VALIDA)

        elif senha_antiga == novasenha:  # retorno > "checa_qualidade"
            print('A nova senha precisa ser diferente da senha antiga.')
        else:
            newhashedpwd = argon2.using(rounds=8, salt_size=128)\
                .hash(novasenha)
            chave = doc['alteracoes_senha'] + 1
            data_alteracao = datetime.now().\
                strftime("%d/%m/%Y %H:%M:%S UTC−03:00")
            if 'data_alteracao_senha' in doc:
                doc['senha'] = newhashedpwd
                doc['data_alteracao_senha'][chave] = data_alteracao
                doc['alteracoes_senha'] += 1
                doc.save()
            else:
                doc['data_alteracao_senha'] = {}  # cria um "nested dic"
                doc['senha'] = newhashedpwd
                doc['data_alteracao_senha'][chave] = data_alteracao
                doc['alteracoes_senha'] += 1
                doc.save()

            print(f'Senha do usuário {usuario} alterada com sucesso.')
    else:
        print(f'Senha antiga inválida para o usuário "{usuario}".')


def remove_usuario():

    print('--- Remoção das credencias usuário ---\n\
    Digite um nome de usuário:')
    if checa_se_usuario_existe() is False:
        exit('Usuário não existe na base')
    doc = BANCODB[usuario]
    print(f'Digite REMOVER para confirmar a remoção do usuário {usuario}')
    checa_resposta = input()
    if checa_resposta == 'REMOVER':
        doc.delete()
        print(f'Usuário {usuario} removido com sucesso.')
    else:
        print('É preciso digitar "REMOVER" para confirmar a remoção.')


def lista_todos_os_usuarios():

    print(f"\n\n[ --- Usuários cadastrados no CouchDB --- ] \n")
    for docs in BANCODB:
        max_alteracoes = docs['alteracoes_senha'] + 1
        print(f"[--] Usuário: \n  "
              f"** Login: {docs['_id']}\n    "
              f"  *** Data de criação das credenciais: {docs['data_criacao']}")
        for alteracoes in range(1, max_alteracoes):
            chave = str(alteracoes)
            data_alteracao = docs['data_alteracao_senha'][chave]
            data_criacao = docs['data_criacao']
            if alteracoes >= 1 and data_criacao != data_alteracao:
                print(f"         *** Data(s) da alteração da senha: "
                      f"{docs['data_alteracao_senha'][chave]}")


def lista_data_de_alteracao_de_senha():

    print('--- Lista data de alteração de senha ---\n\
    Digite um nome de usuário:')
    if checa_se_usuario_existe() is False:
        exit('Usuário não existe na base')
    doc = BANCODB[usuario]
    alteracoes = doc['alteracoes_senha']
    if alteracoes == 0:
        print('Não houve alterações de senha.')
    else:
        print(f"[--] Usuário: \n  "
              f"Login: {doc['_id']}\n")
        for alteracao in range(1, alteracoes + 1):
            chave = str(alteracao)
            data_alteracao = doc['data_alteracao_senha'][chave]
            data_criacao = doc['data_criacao']
            if alteracoes >= 1 and data_criacao != data_alteracao:
                print(f"     ** Data(s) da alteração da senha: "
                      f"{doc['data_alteracao_senha'][chave]}")


def main_menu():

    global escolha
    escolhas = ["[x] Cadastra usuário",
                "[x] Autentica usuário",
                "[x] Altera senha do usuário",
                "[x] Remove usuário",
                "[x] Lista todos os usuários",
                "[x] Lista data de alterações da senha",
                "[x] Sai do programa"]

    escolha = TerminalMenu(menu_entries=escolhas,
                           title=f"{'-' * 16} OPCOES DO MENU {'-' * 16}",
                           menu_cursor="> ",
                           menu_cursor_style=("fg_red", "bold"),
                           menu_highlight_style=("bg_black", "fg_red"),
                           cycle_cursor=True).show()

    return escolha


if __name__ == "__main__":

    try:

        main_menu()
        if escolha == 0:
            cadastra_usuario_no_banco()
        elif escolha == 1:
            autentica_usuario()
        elif escolha == 2:
            altera_senha_de_usuario()
        elif escolha == 3:
            remove_usuario()
        elif escolha == 4:
            lista_todos_os_usuarios()
        elif escolha == 5:
            lista_data_de_alteracao_de_senha()
        elif escolha == 6:
            exit()

    except (ValueError, KeyboardInterrupt) as erro:
        exit(f'Erro >> {erro}')
