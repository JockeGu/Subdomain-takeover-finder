"""
This program "cracks" hashes. It uses wordlists to compare words and hashes to match them together.
"""
import hashlib
import pyfiglet

BANNER = pyfiglet.figlet_format("HashCracker")
print(BANNER)

print("Valid hash algorithms: MD5 | SHA1 | SHA512 | SHA224")
valid_hash_types = ('MD5', 'SHA1', 'SHA512', 'SHA224')
HASH_TYPE = ''

while HASH_TYPE not in valid_hash_types:
    HASH_TYPE = str(input("Choose algorithm: ").upper())
    if HASH_TYPE not in valid_hash_types:
        print("Please enter a valid hashing algorithm.")

wordlist_location = input(str("Enter the location of your wordlist: "))
HASH = str(input("Enter your hash: "))

with open(wordlist_location, 'r', encoding="utf-8") as file:
    wordlist = file.read()

LIST = wordlist.splitlines()

for word in LIST:
    if HASH_TYPE == "MD5":
        hash_object = hashlib.md5(f"{word}".encode('utf-8'))
        HASHED = hash_object.hexdigest()
        if HASH == HASHED:
            print(f"\033[1;32mHASH CRACKED: {word}\033[0m")

    elif HASH_TYPE == "SHA1":
        hash_object = hashlib.sha1(f"{word}".encode('utf-8'))
        HASHED = hash_object.hexdigest()
        if HASH == HASHED:
            print(f"\033[1;32mHASH CRACKED: {word}\033[0m")

    elif HASH_TYPE == "SHA512":
        hash_object = hashlib.sha512(f"{word}".encode('utf-8'))
        HASHED = hash_object.hexdigest()
        if HASH == HASHED:
            print(f"\033[1;32mHASH CRACKED: {word}\033[0m")

    elif HASH_TYPE == "SHA224":
        hash_object = hashlib.sha224(f"{word}".encode('utf-8'))
        HASHED = hash_object.hexdigest()
        if HASH == HASHED:
            print(f"\033[1;32mHASH CRACKED: {word}\033[0m")
