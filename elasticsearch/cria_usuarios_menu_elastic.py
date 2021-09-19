from elasticsearch import Elasticsearch as conexao
from passlib.hash import argon2
from sys import exit as callexit
from stdiomask import getpass
from string import punctuation, digits
from datetime import datetime
from random import choice, SystemRandom
from json import dumps


ESEARCH = conexao(hosts=['http://10.10.10.10:9200'])

POLITICA_SENHA_VALIDA = ('Digite uma senha com 10+ caracteres, 2 dígitos '
                         'e 2 caracteres em caixa alta.')


def cria_indice():

    mapping_userdb = {"mappings":
                      {"properties":
                       {"datas_alteracao_senha": {"type": "nested"},
                        "codigos_de_seguranca": {"type": "nested"},
                        "historico_de_senhas": {"type": "nested"}
                        }}}

    map_megasena = {"mappings":
                    {"properties":
                     {"concurso": {"type": "nested"}
                      }}}

    print(f'|--- SUBMENU DE OPCOES ---|')
    indice_escolha = int(input("1 - userdb\n"
                               "2 - megasena\n"
                               ">>  "))

    if indice_escolha in range(1, 3):
        if indice_escolha == 1:
            if ESEARCH.indices.exists(index="userdb") is False:
                ESEARCH.indices.create(index="userdb", body=mapping_userdb)
            else:
                callexit('Indice existente.')
        elif indice_escolha == 2:
            if ESEARCH.indices.exists(index="megasena") is False:
                ESEARCH.indices.create(index="megasena", body=map_megasena)
            else:
                callexit('Indice existente.')


def remove_indice():

    _confirma, _indice =\
        map(str, input('Forneça:\n Formato: "CONFIRMA|INDICE": ')
            .split('|'))
    if ESEARCH.indices.exists(index=_indice) is True:
        if f'{_confirma}|{_indice}':
            resultado = ESEARCH.indices.delete(index=_indice)
            print(resultado)
        else:
            print('Forneça:\n Formato: "CONFIRMA|INDICE": ')
    else:
        print('Índice não existe no ES.')


def checa_se_usuario_existe():

    global usuario, resultado
    usuario = input('Digite um nome de usuário: ')
    assert usuario, 'Digite um nome de usuário.'
    resultado = ESEARCH.search(
        index="userdb", body={"query": {"match": {"nome": usuario}}})
    if resultado['hits']['hits'] != []:
        return True
        return usuario, resultado
    else:
        return False


def verifica_senha():

    global senha
    if checa_se_usuario_existe() is False:
        callexit('Usuário inexistente.')
    senha = getpass('Senha: ')
    for ocorrencia in resultado['hits']['hits']:
        hashpwd = ocorrencia['_source']['senha']
        if argon2.verify(senha, hashpwd):
            print('Senha correta')
            return True
            return senha
        else:
            print('Senha Incorreta')
            return False


def checa_qualidade_da_senha(senha):

    TAMANHO = len(senha)
    DEC = sum([1 for char in senha if char.isdecimal()])
    UPPER = sum([1 for char in senha if char.isupper()])
    LOWER = sum([1 for char in senha if char.islower()])
    SPACE = sum([1 for char in senha if char.isspace()])
    PUC = sum([1 for char in senha if char in punctuation])
    [POLITICA_DE_SENHA := TAMANHO >= 2 and DEC >= 1 and UPPER >= 1]
    if POLITICA_DE_SENHA:
        return True
        return senha
    else:
        return False


def cadastra_usuario_no_banco():

    global senha
    print('--- Criação das credencias de novo usuário ---\n\
    Digite um nome de usuário:\n')
    if checa_se_usuario_existe():
        callexit('Usuário já existe na base.')
    senha = getpass('Digite uma senha: ')
    if checa_qualidade_da_senha(senha) is True:
        hashedpwd = argon2.using(salt_size=64).hash(senha)
        data = datetime.now().strftime("%m/%d/%Y %H:%M:%S UTC−03:00")
        codigos = {}
        for n in range(1, 9):
            [rd := ''.join(SystemRandom().choice(digits) for _ in range(9))]
            codigos[n] = rd
        credenciais = {'nome': usuario,
                       'senha': hashedpwd,
                       'historico_de_senhas': [{}],
                       'data_criacao': data,
                       'datas_alteracao_senha': [{}],
                       'codigos_de_seguranca': [{'codigos': codigos}],
                       'alteracoes_senha': 0}
        ESEARCH.index(index="userdb", id=usuario, body=credenciais)
        print('Usuário criado com sucesso.')
    else:
        print(POLITICA_SENHA_VALIDA)


def altera_senha_de_usuario():

    global senha
    print('--- Alteração das credencias de usuário ---\n')
    if checa_se_usuario_existe():
        for alt in resultado['hits']['hits']:
            alteracoes = alt['_source']['alteracoes_senha'] + 1
            senha_antiga = alt['_source']['senha']
        senha = getpass(f'Digite a nova senha para o usuário {usuario}: ')
        if argon2.verify(senha, alt['_source']['senha']):
            callexit('Mesma senha anterior. Digite uma nova senha')
        else:
            pass
        if checa_qualidade_da_senha(senha) is True:
            hashedpwd = argon2.using(salt_size=64).hash(senha)
            data = datetime.now().strftime("%m/%d/%Y %H:%M:%S UTC−03:00")
            credenciais = {'doc':
                           {'senha': hashedpwd,
                            'historico_de_senhas': {alteracoes: senha_antiga},
                            'datas_alteracao_senha': {alteracoes: data},
                            'alteracoes_senha': alteracoes}}
            ESEARCH.update(index="userdb", id=usuario, body=credenciais)
            print('Senha alterada com sucesso.')
        else:
            print(POLITICA_SENHA_VALIDA)
    else:
        callexit('Usuário inexistente.')


def remove_usuario():

    opcao = 'noprint'
    if lista_usuarios(opcao) is False:
        callexit()
    else:
        pass
    if checa_se_usuario_existe():
        resultado = ESEARCH.delete_by_query(
            index="userdb", body={"query": {"match": {"nome": usuario}}})
        if resultado['failures'] == []:
            print('Usuário removido')
    else:
        print('Usuário inexistente.')


def lista_usuarios(opcao=None):

    resultado = ESEARCH.search(index="userdb",
                               body={"query": {"match_all": {}}})
    if opcao == 'noprint':
        if resultado['hits']['hits'] != []:
            return True
        else:
            return False
    elif opcao is None:
        if resultado['hits']['hits'] != []:
            for hit in resultado['hits']['hits']:
                print(dumps(hit['_source'], indent=3))
        else:
            print('Não há usuários cadastrados.')


def lista_1_usuario():

    checa_se_usuario_existe()
    for hit in resultado['hits']['hits']:
        user = hit['_source']['nome']
        alteracoes = hit['_source']['datas_alteracao_senha']
        numero = hit['_source']['alteracoes_senha']
        codigos_seguranca = hit['_source']['codigos_de_seguranca']
        for chave in range(1, numero + 1):
            print(user, alteracoes[str(chave)], codigos_seguranca)


def main():

    TRACO = '-' * 13
    print(f'|{TRACO} MENU DE OPCOES {TRACO}|')

    escolha = int(input("1 - Cadastro\n"
                        "2 - Lista Usuários\n"
                        "3 - Procura usuário\n"
                        "4 - Remove usuário\n"
                        "5 - Verifica Senha\n"
                        "6 - Altera senha\n"
                        "7 - Cria indice\n"
                        "8 - Remove indice\n"
                        ">>  "))

    if escolha in range(1, 9):
        if escolha == 1:
            cadastra_usuario_no_banco()
        elif escolha == 2:
            lista_usuarios()
        elif escolha == 3:
            lista_1_usuario()
        elif escolha == 4:
            remove_usuario()
        elif escolha == 5:
            verifica_senha()
        elif escolha == 6:
            altera_senha_de_usuario()
        elif escolha == 7:
            cria_indice()
        elif escolha == 8:
            remove_indice()
    else:
        callexit('Digite uma opção válida do menu')


if __name__ == "__main__":

    try:
        main()
    except ValueError as erro:
        print(f'Erro >> {erro}')
