#!/usr/bin/env python3

import sys
import hashlib
from tqdm import tqdm

if len(sys.argv) != 2:
    print("Invalid Arguments!")
    print(">> {} <sha256sum>".format(sys.argv[0]))
    exit()

wanted_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0

with tqdm(total=100, desc="Attempting to crack hash") as p:
    with open(password_file, "r", encoding='latin-1') as password_list:
        for password in password_list:
            password = password.strip("\n").encode('latin-1')
            password_hash = hashlib.sha256(password).hexdigest()
            p.set_description("Attempting to crack hash - Attempt {}".format(attempts))
            p.update(1)
            if password_hash == wanted_hash:
                p.set_description("Hash cracked!")
                p.close()
                print("Password hash found after {} attempts! Password: {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()
            attempts += 1

print("Password hash not found after {} attempts!".format(attempts))
