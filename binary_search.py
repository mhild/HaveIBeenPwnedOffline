#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals
from hashlib import sha1
from os import stat
from argparse import ArgumentParser

from pykeepass import PyKeePass
import getpass


def binary_search(hex_hash, list_file, file_size):
    def get_full_line(file, pos):
        file.seek(pos)
        while pos > 0 and file.read(1) != "\n":
            pos -= 1
            file.seek(pos)
        return file.readline(), pos

    def search_hash(file, my_hash, start, end):
        if start >= end:
            return 0
        new_pos = start + (end - start) // 2
        candidate_line, pivot = get_full_line(file, new_pos)
        # print("Trying line at pos {:11d}: \"{}\" (pivot position: {})".format(
        #     new_pos, candidate_line.strip(), pivot))
        pwned_hash, count = candidate_line.split(':')
        if pwned_hash == my_hash:
            print("Password found at byte {:11d}: \"{}\"".format(pivot, candidate_line.strip()))
            return int(count.strip())
        if my_hash > pwned_hash:
            return search_hash(file, my_hash, file.tell(), end)
        else:
            return search_hash(file, my_hash, start, pivot)

    return search_hash(list_file, hex_hash, 0, file_size)

def check_password(password, pwned_passwords_file, pwned_passwords_file_size):
    if 'decode' in dir(str):
        password = password.decode('utf-8')
    encodings = ['utf-8', 'latin', 'iso8859-15', 'iso8859-1']
    hashes = []
    for encoding in encodings:
        try:
            hash_candidate = sha1(password.encode(encoding)).hexdigest().upper()
            if hash_candidate not in hashes:
                hashes.append(hash_candidate)
        except UnicodeEncodeError:
            continue
    count = 0   
    for h in hashes:
   #     print("Searching for hash {}.".format(h))
        count += binary_search(h, pwned_passwords_file, pwned_passwords_file_size) 

    return count

        

if __name__ == "__main__":
    parser = ArgumentParser(description='Test passwords locally.' +
                                        ' Each password you pass as an argument will be hashed and this script' +
                                        ' will search for the hash in the list.')
    parser.add_argument('passwords', nargs='*')
    parser.add_argument('--kdbx', default="", required=False)
    parser.add_argument('--pwned-passwords-ordered-by-hash-filename', required=False, 
                        default="pwned-passwords-sha1-ordered-by-hash-v4.txt")
    args = parser.parse_args()
    
    if len(args.passwords) == 0 and args.kdbx=="":
        print("You have either have to specify single passwords or the path to a kdbx-file (option --kdbx)")
        exit
        
    with open(args.pwned_passwords_ordered_by_hash_filename, 'r') as pwned_passwords_file:
        pwned_passwords_file_size = stat(args.pwned_passwords_ordered_by_hash_filename).st_size
        # print("File size: {} Bytes".format(pwned_passwords_file_size))
        for password in args.passwords:
            count = check_password(password, pwned_passwords_file, pwned_passwords_file_size)
            if count > 0:
                print("Your password \"{}\" was in {} leaks or hacked databases!".format(password, count) +
                      " Please change it immediately.")
            else:
                print("Your password \"{}\" is not in the dataset. You may relax.".format(password))
        
        if not args.kdbx=="":
            store_password = getpass.getpass("Password of kdbx-file")
            kdbx = PyKeePass(args.kdbx, store_password)
            
            for entry in kdbx.entries:
                if entry.password:
                    # print("Checking entry \"{}\"".format(entry))
                    count = check_password(entry.password, pwned_passwords_file, pwned_passwords_file_size)
                    if count > 0:
                        print("Your password of \"{}\"was in {} leaks or hacked databases!".format(entry, count) +
                          " Please change it immediately.")
                        if entry.notes:
                            entry.notes = "{}\n\nPassword was in {} leak(s)!".format(entry.notes, count)
                        else:
                            entry.notes = "Password was in {} leak(s)!".format(count)
#                    else:
#                        print("Your password is not in the dataset. You may relax.")
            kdbx.save()
                
