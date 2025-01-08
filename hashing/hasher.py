"""
This program hashes you given strings into MD5, SHA1, SHA512 or SHA224.
"""
import hashlib


def hasher():
    """
    This function hashes your string into MD5, SHA1, SHA512 or SHA224.
    """
    print("Available hashing options: MD5 | SHA1 | SHA512 | SHA224 ")

    valid_options = ('MD5', 'SHA1', 'SHA512', 'SHA224')
    hash_option = ''

    while hash_option not in valid_options:
        hash_option = str(input("Enter hashing algorithm: ").upper())
        if hash_option not in valid_options:
            print("Please enter at valid hashing algorithm.")

    if hash_option == 'MD5':
        user_input = str(input("Enter password to hash: "))
        hash_object = hashlib.md5(f"{user_input}".encode('ASCII'))
        hashed = hash_object.hexdigest()
        print(f"\033[1;32mYour hash: {hashed}\033[0m")

    if hash_option == 'SHA1':
        user_input = str(input("Enter password to hash: "))
        hash_object = hashlib.SHA1(f"{user_input}".encode('ASCII'))
        hashed = hash_object.hexdigest()
        print(f"\033[1;32mYour hash: {hashed}\033[0m")

    if hash_option == 'SHA512':
        user_input = str(input("Enter password to hash: "))
        hash_object = hashlib.SHA512(f"{user_input}".encode('ASCII'))
        hashed = hash_object.hexdigest()
        print(f"\033[1;32mYour hash: {hashed}\033[0m")

    if hash_option == 'SHA224':
        user_input = str(input("Enter password to hash: "))
        hash_object = hashlib.SHA224(f"{user_input}".encode('ASCII'))
        hashed = hash_object.hexdigest()
        print(f"\033[1;32mYour hash: {hashed}\033[0m")

hasher()
