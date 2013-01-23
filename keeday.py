#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# keeday - password derivation tool
# TomCrypto (contact: github)
# Header written 23 Jan 2013

from os.path import expanduser
from getpass import getpass
from getpass import getuser
from os.path import isfile
from pbkdf2 import pbkdf2

from base64 import b64encode
from base64 import b64decode

from hashlib import sha512
import hmac
import json
import sys
import os

# Number of KDF iterations, the higher the better, but the higher the slower it
# will take to look up a password. Usually a few thousand iterations is good.
ITERS = 25000

# Number of base characters in the generated passwords, note this excludes any
# extra special characters which are always added to the passwords.
CHARS = 30

# This is a constant salt for the actual password generation derived key. This
# is because I wanted the generated passwords to depend only on the passphrase
# in case the password entry file was lost or corrupted. I don't believe there
# is a security concern in doing this, as the other hash for authentication is
# using a pseudorandom salt. In any case, the iteration count is high enough.
SALT = bytes([0x00] * 64)

DEFAULT = '''{"passphrase":
          {"authsalt": "",
           "authhash": ""},
           "pwentry" : []}'''

def GenAuth(passphrase):
    authSalt = os.urandom(64)
    hashSalt = SALT 

    kdf = pbkdf2(sha512, passphrase.encode("utf-8"), authSalt, ITERS, 64)

    return (b64encode(authSalt).decode("utf-8"),
            b64encode(kdf).decode("utf-8"))

def GetAuth(passphrase, authSalt):
    salt = b64decode(authSalt.encode("utf-8"))

    kdf = pbkdf2(sha512, passphrase.encode("utf-8"), salt, ITERS, 64)
    return b64encode(kdf).decode("utf-8")

class Manager:
    def __init__(self, username):
        self.user = username
        if not os.path.exists(expanduser("~") + "/.keeday/"):
            os.makedirs(expanduser("~") + "/.keeday/")

        self.path = expanduser("~") + "/.keeday/" + self.user + ".key"

        if isfile(self.path):
            self.data = json.loads(open(self.path, "r").read())
        else:
            self.data = json.loads(DEFAULT)

    def Finish(self):
        open(self.path, "w").write(json.dumps(self.data))

    def ChangePassphrase(self, passphrase):
        tag = GenAuth(passphrase)

        self.data["passphrase"]["authsalt"] = tag[0]
        self.data["passphrase"]["authhash"] = tag[1]

    def CheckPassphrase(self, passphrase):
        authSalt = self.data["passphrase"]["authsalt"]
        kdf = GetAuth(passphrase, authSalt)
        
        # Compare the expected and actual auth tags
        if self.data["passphrase"]["authhash"] != kdf:
            return False
        else:
            return True

    def Index(self, category, service, identifier):
        for t in self.data["pwentry"]:
            if t["category"] == category:
                if t["service"] == service:
                    if t["identifier"] == identifier:
                        return t

        return -1

    def Delete(self, category, service, identifier):
        v = self.Index(category, service, identifier)
        if v == -1:
            return False

        for t in range(len(self.data["pwentry"])):
            v = self.data["pwentry"][t]
            if v["category"] == category:
                if v["service"] == service:
                    if v["identifier"] == identifier:
                        del self.data["pwentry"][t]
                        return True

    def Add(self, category, service, identifier):
        if self.Index(category, service, identifier) != -1:
            return False

        x = dict([("category", category),
                  ("service", service),
                  ("identifier", identifier),
                  ("counter", 0)])

        # Add this entry to list
        self.data["pwentry"].append(x)
        return True

    def Update(self, category, service, identifier):
        v = self.Index(category, service, identifier)
        if v == -1:
            return False
        else:
            v["counter"] += 1
            return True

    def Revert(self, category, service, identifier):
        v = self.Index(category, service, identifier)
        if v == -1:
            return False

        if v["counter"] == 0:
            return -1
        else:
            v["counter"] -= 1
            return True

    def GetPassword(self, passphrase, category, service, identifier):
        if not self.CheckPassphrase(passphrase):
            return False

        v = self.Index(category, service, identifier)
        if v == -1:
            return False

        # Get the passphrase-only derived hashing key (constant salt)
        kdf = pbkdf2(sha512, passphrase.encode("utf-8"), SALT, ITERS, 64)

        # This is where the cryptography really happens
        a = hmac.new(kdf, category.encode("utf-8"), sha512).digest()
        b = hmac.new(kdf, service.encode("utf-8"), sha512).digest()
        c = hmac.new(kdf, identifier.encode("utf-8"), sha512).digest()
        d = hmac.new(kdf, v["counter"].to_bytes(8, 'big'), sha512).digest()

        output = hmac.new(kdf, a + b + c + d, sha512).digest()
        pw = b64encode(output).decode("utf-8")
        return "#" + pw[:CHARS] + "==" # enforce special characters

################################################################################
############################# ACTUAL SCRIPT BELOW  #############################
################################################################################

# Try and be intelligent and assume user name may be omitted

if len(sys.argv) == 2:
    sys.argv.append(getuser())
    print("Assuming user '" + sys.argv[2] + "'...")

if len(sys.argv) == 5:
    sys.argv.insert(2, getuser())
    print("Assuming user '" + sys.argv[2] + "'...")

if len(sys.argv) < 2:
    sys.exit()

if sys.argv[1] == "--new":
    try:
        passphrase = getpass("New passphrase: ")
        confirm    = getpass("Please confirm: ")
        if passphrase != confirm:
            print("Passphrases do not match.")
            os._exit(1)
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        f.ChangePassphrase(confirm)
        f.Finish()
    except:
        print("An error occurred!")
    
    sys.exit()

if sys.argv[1] == "--add":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        if not f.Add(sys.argv[3], sys.argv[4], sys.argv[5]):
            print("This entry already exists.")

        f.Finish()
    except:
        print("An error occurred!")

    sys.exit()

if sys.argv[1] == "--passphrase":
    try:
        passphrase = getpass("New passphrase: ")
        confirm    = getpass("Please confirm: ")
        if passphrase != confirm:
            print("Passphrases do not match.")
            os._exit(1)
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        f.ChangePassphrase(confirm)
        f.Finish()
    except:
        print("An error occurred!")

    sys.exit()

if sys.argv[1] == "--update":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        if not f.Update(sys.argv[3], sys.argv[4], sys.argv[5]):
            print("This entry does not exist.")

        f.Finish()
    except:
        print("An error occurred!")

    sys.exit()

if sys.argv[1] == "--revert":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        r = f.Revert(sys.argv[3], sys.argv[4], sys.argv[5])
        if r != True:
            if r == False:
                print("The entry does not exist.")
            else:
                print("This entry has not been updated yet - cannot revert.")

        f.Finish()
    except:
        print("An error occurred!")
        
    sys.exit()

if sys.argv[1] == "--delete":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        if not f.Delete(sys.argv[3], sys.argv[4], sys.argv[5]):
            print("This entry does not exist.")

        f.Finish()
    except:
        print("An error occurred!")

    sys.exit()

if sys.argv[1] == "--get":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2])
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        s = f.GetPassword(passphrase, sys.argv[3], sys.argv[4], sys.argv[5])

        if s == False:
            print("This entry does not exist.")
            os._exit(1)

        print("Password: " + s)
        f.Finish()
    except:
        print("An error occurred!")

    sys.exit()

if sys.argv[1] == "--remove":
    path = expanduser("~") + "/.keeday/" + sys.argv[2] + ".key"
    
    if not isfile(path):
        print("No such user exists.")
        sys.exit()

    try:
        i = input("Are you sure you wish to remove user '"
                  + sys.argv[2] + "'? Y/n: ")
    except:
        print("")
        sys.exit()

    if i != "Y":
        print("Operation aborted.")
        sys.exit()
    else:
        try:
            os.remove(path)
        except:
            print("An error occurred!")

    sys.exit()

print("Command '" + sys.argv[1] + "' not recognized.")
