#
# Aplicación que permite conocer cuan comun es un password determinado
# El password introducido NO ES ENVIADO sobre internet, ni persiste en su sistema ni archivo alguno.
# La aplicación devuelve un número, cuanto mayor es éste, mas común es el password introducido.
# Se basa en servicios de API PASSWORD de PWNED

import requests
import hashlib


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hash_list = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hash_list:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    first_5_chars, tail = sha1password[:5], sha1password[5:]
    response = request_api_data((first_5_chars))
    return get_password_leaks_count(response, tail)


while True:
    password = str(input('Ingrese password a chequear: '))
    print(pwned_api_check(password))
