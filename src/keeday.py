#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# keeday - password derivation tool
# TomCrypto (contact: github)
# Header written 23 Jan 2013

# File and folder management imports
from os.path import expanduser, exists, isfile
from getpass import getpass
from os import makedirs

# Cryptographic/encoding imports
from base64 import b64encode, b64decode
from hashlib import sha512
from pbkdf2 import pbkdf2
import hmac

# Miscellaneous imports
import json, sys, os

# Number of KDF iterations, the higher the better but the higher the slower it
# will take to look up a password. Usually a few thousand iterations is good.
KDF_ITER = 40000
# default: 40000

# Length of the salt and of the authentication hash, in bytes. This should be,
# at the very least, 16, and has a maximum value of 64 (512 bits).
SALT_LEN = 40
# default: 40

# Number of base characters in the generated passwords, note this includes any
# extra special characters which are always added to the passwords in order to
# fulfill the stupid "special character" requirements of some websites. Please
# note you should avoid changing this too often as it is not on a per-password
# basis and will get confusing. The default value should be good. Maximum: 88.
PASS_LEN = 88
# default: 25

# The output size of the SHA-512 hash function. This better be equal to 64.
SIZE = sha512().digest_size

# This is a default empty user file which contains the required JSON fields
EMPTY = '''{"authentication":{"auth_salt":"","auth_hash":"","iteration":0},
            "entries":[]}'''

class Manager:
    ''' This will open the corresponding user file. If the file is supposed to
    exist but doesn't, or vice versa, the method will fail & return False. '''
    def __init__(self, user, mustexist):
        p = expanduser("~") + "/.keeday/"
        self.path = [p, p + user + ".key"]

        # Create /.keeday/ if needed
        if not exists(self.path[0]):
            makedirs(self.path[0])

        if isfile(self.path[1]) ^ mustexist:
            if mustexist:
                # I realize raising an assertion exception is unconventional,
                # but technically, the code asserts the user knows what he is
                # doing, in such a way that this code path is never taken :]
                raise AssertionError("User does not exist.")
            else:
                raise AssertionError("User already exists.")

        if mustexist:
            with open(self.path[1], "r") as userfile:
                self.data = json.loads(userfile.read())
        else:
            self.data = json.loads(EMPTY)

    ''' This method will remove the user and delete his file. '''
    def RemoveUser(self):
        os.remove(self.path[1])

    ''' This method will save the current data to the user's file. '''
    def Finish(self):
        output = json.dumps(self.data, indent = 2, sort_keys = True)
        with open(self.path[1], "w") as userfile:
            userfile.write(output + "\n")

    ''' This method will change the user's passphrase to the argument. '''
    def ChangePassphrase(self, passphrase):
        msg = passphrase.encode("utf-8")
        salt = os.urandom(SALT_LEN)

        self.key = pbkdf2(sha512, msg, salt, KDF_ITER, SIZE)
        auth = sha512(self.key).digest()[:len(salt)]

        salt_str = b64encode(salt).decode("utf-8")
        auth_str = b64encode(auth).decode("utf-8")

        self.data["authentication"]["auth_salt"] = salt_str
        self.data["authentication"]["auth_hash"] = auth_str
        self.data["authentication"]["iteration"] = KDF_ITER

    ''' This method will verify the passphrase against the user's current one,
    returning True if the given passphrase is correct and False otherwise. '''
    def CheckPassphrase(self, passphrase):
        msg = passphrase.encode("utf-8")
        salt_str = self.data["authentication"]["auth_salt"]
        auth_str = self.data["authentication"]["auth_hash"]
        iter_cnt = self.data["authentication"]["iteration"]

        salt = b64decode(salt_str.encode("utf-8"))
        self.key = pbkdf2(sha512, msg, salt, iter_cnt, SIZE)
        comp = sha512(self.key).digest()[:len(salt)]
        comp_str = b64encode(comp).decode("utf-8")

        return comp_str == auth_str

    ''' This method will find a given password entry, optionally deleting it.
    If the entry does not exist in the file the method will return False. '''
    def Find(self, category, service, identifier, delete = False):
        for entry in self.data["entries"]:
            if entry["category"]   == category and \
               entry["service"]    == service  and \
               entry["identifier"] == identifier:
                if not delete:
                    return entry

                self.data["entries"].remove(entry)
                return True

        return False

    ''' This method returns whether a password entry exists. '''
    def Exists(self, category, service, identifier):
        return self.Find(category, service, identifier) != False

    ''' This method deletes an existing password entry. '''
    def Delete(self, category, service, identifier):
        entry = self.Find(category, service, identifier, True)
        return entry

    ''' This method will add a password entry to the file. '''
    def Add(self, category, service, identifier):
        if self.Exists(category, service, identifier):
            return False

        entry = {"category"  : category,
                 "service"   : service,
                 "identifier": identifier,
                 "counter"   : 0}

        self.data["entries"].append(entry)
        return True

    ''' This method will update an existing password entry. '''
    def Update(self, category, service, identifier):
        entry = self.Find(category, service, identifier)
        if not entry:
            return False

        entry["counter"] += 1
        return True

    ''' This method will revert an existing password entry. '''
    def Revert(self, category, service, identifier):
        entry = self.Find(category, service, identifier)
        if not entry or entry["counter"] == 0:
            return False

        entry["counter"] -= 1
        return True

    ''' This method will generate and return the requested password. '''
    def GetPassword(self, passphrase, category, service, identifier):
        entry = self.Find(category, service, identifier)
        if not entry:
            return False

        # Convert each token to a binary format
        tokenA = entry["category"].encode("utf-8")
        tokenB = entry["service"].encode("utf-8")
        tokenC = entry["identifier"].encode("utf-8")
        tokenD = entry["counter"].to_bytes(8, "big")

        # Check that the passphrase is correct
        if not self.CheckPassphrase(passphrase):
            raise AssertionError("Incorrect passphrase.")

        # This is where the cryptography really happens
        a = hmac.new(self.key, tokenA, sha512).digest()
        b = hmac.new(self.key, tokenB, sha512).digest()
        c = hmac.new(self.key, tokenC, sha512).digest()
        d = hmac.new(self.key, tokenD, sha512).digest()

        # Note a + b + c + d represents concatenation in this case!
        output = hmac.new(self.key, a + b + c + d, sha512).digest()
        
        # Truncate base64 from the right to keep padding bits 
        password = b64encode(output, b"#+").decode("utf-8")
        return password[len(password) - PASS_LEN:]

################################################################################
############################# ACTUAL SCRIPT BELOW  #############################
################################################################################

# Handle the --help command separately
if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == "--help"):
    print("This is keeday, a password derivation tool. Usage:\n")
    print("[user] --new                    Creates new user.")
    print("[user] --remove                 Removes existing user.")
    print("[user] --passphrase             Changes user passphrase.")
    print("[user] --format                 Restores user file formatting.\n")
    print("[user] --add    [c] [s] [i]     Creates new password entry for")
    print("                                category [c], service [s], and")
    print("                                identifier [i], and stores it.")
    print("[user] --delete [c] [s] [i]     Deletes password entry.")
    print("[user] --update [c] [s] [i]     Updates password entry.")
    print("[user] --revert [c] [s] [i]     Reverts password entry update.")
    print("[user] --get    [c] [s] [i]     Derives password for entry.\n")
    print("       --help                   Displays this help page.\n")
    print("See the README file for an introduction, or consult the man page.")
    sys.exit()

# First, verify that the arguments make sense
if len(sys.argv) != 3 and len(sys.argv) != 6:
    print("Invalid arguments.")
    sys.exit()

# Store arguments
user = sys.argv[1]
cmd  = sys.argv[2]
if len(sys.argv) == 6:
    arg1 = sys.argv[3]
    arg2 = sys.argv[4]
    arg3 = sys.argv[5]

short_cmd = ["--new", "--passphrase", "--remove", "--format"]
long_cmd = ["--add", "--delete", "--update", "--revert", "--get"]
count = len(sys.argv)

if (count == 6 and cmd in short_cmd) or (count == 3 and cmd in long_cmd):
    print("Invalid arguments.")
    sys.exit()

try:
    if cmd == "--new" or cmd == "--passphrase":
        # Create a new user file
        f = Manager(user, cmd == "--passphrase")
            
        try:
            passphrase = getpass("New passphrase: ")
            confirm    = getpass("Please confirm: ")
            matching = (passphrase == confirm)
        except:
            matching = False
            print("") # for presentation

        if not matching:
            print("Passphrases do not match.")
        else:
            f.ChangePassphrase(passphrase)
            f.Finish()

    elif cmd == "--update" or cmd == "--revert" or cmd == "--delete":
        f = Manager(user, True)
        if cmd == "--update":
            if not f.Update(arg1, arg2, arg3):
                print("Entry does not exist.")

        if cmd == "--revert":
            if not f.Revert(arg1, arg2, arg3):
                if f.Exists(arg1, arg2, arg3):
                    print("Entry has not been updated yet - cannot revert.")
                else:
                    print("Entry does not exist.")

        if cmd == "--delete":
            if not f.Delete(arg1, arg2, arg3):
                print("Entry does not exist.")

        f.Finish()

    elif cmd == "--add":
        f = Manager(user, True)

        if not f.Add(arg1, arg2, arg3):
            print("Entry already exists.")

        f.Finish()

    elif cmd == "--format":
        f = Manager(user, True)
        f.Finish()

    elif cmd == "--remove":
        f = Manager(user, True)

        try:
            p = input("Are you sure you wish to remove user '" + user +
                      "'? Y/n: ")
        except:
            print("")
            p = "n"

        if p != "Y":
            print("User removal aborted.")
        else:
            f.RemoveUser()

    elif cmd == "--get":
        f = Manager(user, True)
        if not f.Exists(arg1, arg2, arg3):
            print("Entry does not exist.")
        else:
            try:
                passphrase = getpass("Passphrase: ")
            except:
                passphrase = ""
                print("")

            pw = f.GetPassword(passphrase, arg1, arg2, arg3)
            if not pw:
                print("Entry does not exist.") # should not happen
            else:
                print("Password  : " + pw)

    else:
        print("Command not recognized.")

except Exception as e:
    print(e)
