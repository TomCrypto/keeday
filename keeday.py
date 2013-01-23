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
AUTH_ITERS = 25000 # default: 25000
HMAC_ITERS = 25000 # default: 25000

# Length of the salt and KDF, in bytes. This should be at the very least 16.
S_LEN = 40 # default: 40

# Number of base characters in the generated passwords, note this excludes any
# extra special characters which are always added to the passwords in order to
# fulfill the stupid "special character" requirements of some websites. Please
# note you should avoid changing this too often, as it can get quite confusing
# once you have many passwords in use. The default value should be good.
PW_CHARS = 30 # default: 30

# This is a constant salt for the actual password generation derived key. This
# is because I wanted the generated passwords to depend only on the passphrase
# in case the password entry file was lost or corrupted. I don't believe there
# is a security concern in doing this, as the other hash for authentication is
# using a pseudorandom salt. In any case, the iteration count is high enough.
SALT = bytes([0x00] * sha512().digest_size)

DEFAULT = '''{"passphrase":{
              "authsalt": "",
              "authhash": "",
              "salt_len":  0,
              "iter_cnt":  0},
              "pw_entry": []}'''

def GenAuth(passphrase):
    authSalt = os.urandom(S_LEN)

    msg = passphrase.encode("utf-8")
    kdf = pbkdf2(sha512, msg, authSalt, AUTH_ITERS, S_LEN)

    return (b64encode(authSalt).decode("utf-8"),
            b64encode(kdf).decode("utf-8"))

def GetAuth(passphrase, authSalt, iters, saltlen):
    salt = b64decode(authSalt.encode("utf-8"))

    kdf = pbkdf2(sha512, passphrase.encode("utf-8"), salt, iters, saltlen)
    return b64encode(kdf).decode("utf-8")

class Manager:
    def __init__(self, username, existing):
        self.user = username
        if not os.path.exists(expanduser("~") + "/.keeday/"):
            os.makedirs(expanduser("~") + "/.keeday/")

        self.path = expanduser("~") + "/.keeday/" + self.user + ".key"

        if isfile(self.path):
            if not existing:
                print("This user already exists.")
                os._exit(1) # I know..

            self.data = json.loads(open(self.path, "r").read())
        else:
            if existing:
                print("This user does not exist.")
                os._exit(1)

            self.data = json.loads(DEFAULT)

    def Finish(self):
        output = json.dumps(self.data, indent = 2, sort_keys = True)
        open(self.path, "w").write(output + "\n")

    def ChangePassphrase(self, passphrase):
        tag = GenAuth(passphrase)

        self.data["passphrase"]["authsalt"] = tag[0]
        self.data["passphrase"]["authhash"] = tag[1]
        self.data["passphrase"]["salt_len"] = S_LEN
        self.data["passphrase"]["iter_cnt"] = AUTH_ITERS

    def CheckPassphrase(self, passphrase):
        authSalt = self.data["passphrase"]["authsalt"]
        iters = self.data["passphrase"]["iter_cnt"]
        saltlen = self.data["passphrase"]["salt_len"]
        kdf = GetAuth(passphrase, authSalt, iters, saltlen)

		# Sanity check...
        if saltlen == 0 or iters == 0:
            return False
        
        # Compare the expected and actual auth tags
        if self.data["passphrase"]["authhash"] != kdf:
            return False
        else:
            return True

    def Index(self, category, service, identifier):
        for t in self.data["pw_entry"]:
            if t["category"] == category:
                if t["service"] == service:
                    if t["identifier"] == identifier:
                        return t

        return -1

    def Delete(self, category, service, identifier):
        v = self.Index(category, service, identifier)
        if v == -1:
            return False

        for t in range(len(self.data["pw_entry"])):
            v = self.data["pw_entry"][t]
            if v["category"] == category:
                if v["service"] == service:
                    if v["identifier"] == identifier:
                        del self.data["pw_entry"][t]
                        return True

    def Add(self, category, service, identifier):
        if self.Index(category, service, identifier) != -1:
            return False

        x = dict([("category", category),
                  ("service", service),
                  ("identifier", identifier),
                  ("counter", 0)])

        # Add this entry to list
        self.data["pw_entry"].append(x)
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
        v = self.Index(category, service, identifier)
        if v == -1:
            return False

        # Get the passphrase-only derived hashing key (constant salt)
        size = sha512().digest_size
        msg = passphrase.encode("utf-8")
        kdf = pbkdf2(sha512, msg, SALT, HMAC_ITERS, size)

        # This is where the cryptography really happens
        a = hmac.new(kdf, category.encode("utf-8"), sha512).digest()
        b = hmac.new(kdf, service.encode("utf-8"), sha512).digest()
        c = hmac.new(kdf, identifier.encode("utf-8"), sha512).digest()
        d = hmac.new(kdf, v["counter"].to_bytes(8, 'big'), sha512).digest()

        # Note + is concatenation (||) here!
        output = hmac.new(kdf, a + b + c + d, sha512).digest()
        pw = b64encode(output).decode("utf-8")
        return "#" + pw[:PW_CHARS] + "==" # enforce special characters

################################################################################
############################# ACTUAL SCRIPT BELOW  #############################
################################################################################

# Try and be intelligent and assume user name may be omitted

if len(sys.argv) == 2 or len(sys.argv) == 5:
    sys.argv.insert(2, getuser())
    print("Assuming user '" + sys.argv[2] + "'...")

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
        f = Manager(sys.argv[2], False)
        f.ChangePassphrase(confirm)
        f.Finish()
    except:
        print("An error occurred!")

elif sys.argv[1] == "--add":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2], True)
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        if not f.Add(sys.argv[3], sys.argv[4], sys.argv[5]):
            print("This entry already exists.")

        f.Finish()
    except:
        print("An error occurred!")

elif sys.argv[1] == "--passphrase":
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
        f = Manager(sys.argv[2], True)
        f.ChangePassphrase(confirm)
        f.Finish()
    except:
        print("An error occurred!")

elif sys.argv[1] == "--update":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2], True)
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        if not f.Update(sys.argv[3], sys.argv[4], sys.argv[5]):
            print("This entry does not exist.")

        f.Finish()
    except:
        print("An error occurred!")

elif sys.argv[1] == "--revert":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2], True)
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

elif sys.argv[1] == "--delete":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2], True)
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        if not f.Delete(sys.argv[3], sys.argv[4], sys.argv[5]):
            print("This entry does not exist.")

        f.Finish()
    except:
        print("An error occurred!")

elif sys.argv[1] == "--get":
    try:
        passphrase = getpass("Passphrase: ")
    except:
        print("")
        sys.exit()

    try:
        f = Manager(sys.argv[2], True)
        if not f.CheckPassphrase(passphrase):
            print("Incorrect passphrase.")
            os._exit(1)

        s = f.GetPassword(passphrase, sys.argv[3], sys.argv[4], sys.argv[5])

        if s == False:
            print("This entry does not exist.")
            os._exit(1)

        print("Password  : " + s)
        f.Finish()
    except:
        print("An error occurred!")

elif sys.argv[1] == "--remove":
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

elif sys.argv[1] == "--format":
	try:
		# Simply passthrough the user file
		f = Manager(sys.argv[2], True)
		f.Finish()

	except:
		print("An error occurred.")

else:
	print("Command '" + sys.argv[1] + "' not recognized.")
