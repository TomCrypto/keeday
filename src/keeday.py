#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# keeday - password derivation tool
# TomCrypto (contact: github)
# Header written 23 Jan 2013
# Last update on  3 Jun 2013

# Operating system and filesystem management modules
from os.path import expanduser, exists, isfile
from getpass import getpass
from os import makedirs

# Cryptographic and byte encoding imports
from base64 import b64encode, b64decode
from hashlib import sha512
from pbkdf2 import pbkdf2
from struct import pack
import hmac

# Miscellaneous imports
import json, sys, os
import argparse
import pwfmt

# Number of KDF iterations, the higher the better but the higher the slower it
# will take to look up a password. Usually a few thousand iterations is good.
KDF_ITER = 40000
# default: 40000

# Length of the salt and of the authentication hash, in bytes. This should be,
# at the very least, 16, and has a maximum value of 64 (512 bits).
SALT_LEN = 40
# default: 40

# This is a default empty user file which contains the required JSON fields
EMPTY = '''{"authentication":{"auth_salt":"","auth_hash":"","iteration":0},
            "entries":[]}'''

# This is a basic constant time comparison, I know there's one in the Python
# library but it's 3.3+ only and I'm going for full Python 3.* compatibility
def ccmp(a, b):
    compare = 0

    # Credit to Nate Lawson for this code snippet taken from the following:
    # http://rdist.root.org/2010/01/07/timing-independent-array-comparison/
    for x, y in zip(a, b):
        compare |= x ^ y

    return compare == 0

class Manager:
    def __init__(self, user, mustexist):
        p = expanduser("~") + "/.keeday/"
        self.path = [p, p + user + ".key"]

        # Create ~/.keeday/ if needed
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

    def RemoveUser(self):
        os.remove(self.path[1])

    def Finish(self):
        output = json.dumps(self.data, indent = 2, sort_keys = True)
        with open(self.path[1], "w") as userfile:
            userfile.write(output + "\n")

    def Entries(self):
        return self.data["entries"]

    def ChangePassphrase(self, passphrase):
        pw = passphrase.encode("utf-8")
        salt = os.urandom(SALT_LEN)

        self.key = pbkdf2(sha512, pw, salt, KDF_ITER, sha512().digest_size)
        auth = sha512(self.key).digest()[:len(salt)]

        salt_str = b64encode(salt).decode("utf-8")
        auth_str = b64encode(auth).decode("utf-8")

        self.data["authentication"]["auth_salt"] = salt_str
        self.data["authentication"]["auth_hash"] = auth_str
        self.data["authentication"]["iteration"] = KDF_ITER

    def CheckPassphrase(self, passphrase):
        pw = passphrase.encode("utf-8")
        salt_str = self.data["authentication"]["auth_salt"]
        auth_str = self.data["authentication"]["auth_hash"]
        iter_cnt = self.data["authentication"]["iteration"]

        salt = b64decode(salt_str.encode("utf-8"))
        self.key = pbkdf2(sha512, pw, salt, iter_cnt, sha512().digest_size)

        comp = sha512(self.key).digest()[:len(salt)]
        auth = b64decode(auth_str.encode("utf-8"))

        return ccmp(comp, auth)

    def Find(self, service, identifier, delete = False):
        for entry in self.data["entries"]:
            if entry["service"]    == service and \
               entry["identifier"] == identifier:
                if not delete:
                    return entry

                self.data["entries"].remove(entry)
                return True

        return False

    def Exists(self, service, identifier):
        return self.Find(service, identifier) != False

    def Delete(self, service, identifier):
        return self.Find(service, identifier, True)

    def Add(self, service, identifier, fmt, param):
        if self.Exists(service, identifier):
            return False

        try:
            # Check if format is valid
            fmtClass = getattr(pwfmt, fmt)
        except:
            raise AssertionError("Unknown format.")

        if param is None:
            param = fmtClass.default()

        if not fmtClass.validate(param):
            raise AssertionError("Invalid parameter.")

        entry = {"service"   : service,
                 "identifier": identifier,
                 "counter"   : 0,
                 "format"    : fmt,
                 "param"     : param}

        self.data["entries"].append(entry)
        return True

    def Update(self, service, identifier):
        entry = self.Find(service, identifier)
        if not entry:
            return False

        entry["counter"] += 1
        return True

    def Revert(self, service, identifier):
        entry = self.Find(service, identifier)
        if not entry or entry["counter"] == 0:
            return False

        entry["counter"] -= 1
        return True

    def GetPassword(self, passphrase, service, identifier):
        entry = self.Find(service, identifier)
        if not entry:
            return False

        # Convert each token to a binary format
        tokenA = entry["service"].encode("utf-8")
        tokenB = entry["identifier"].encode("utf-8")
        tokenC = pack(">Q", entry["counter"]) # 64-bit counter

        # Check that the passphrase is correct
        if not self.CheckPassphrase(passphrase):
            raise AssertionError("Incorrect passphrase.")

        # This is where the cryptography really happens
        a = hmac.new(self.key, tokenA, sha512).digest()
        b = hmac.new(self.key, tokenB, sha512).digest()
        c = hmac.new(self.key, tokenC, sha512).digest()

        # Note a + b + c represents concatenation in this case!
        output = hmac.new(self.key, a + b + c, sha512).digest()
        
        # Get the proper password formatter class 
        fmtClass = getattr(pwfmt, entry["format"])
        return fmtClass.format(output, entry["param"])

################################################################################
############################# ACTUAL SCRIPT BELOW  #############################
################################################################################

def main():
    master = argparse.ArgumentParser(description = "Password derivation tool."
                                     " See README, or consult the man pages.")

    subparsers = master.add_subparsers(dest = "command")

    # List of all commands with their description
    commands = {"new"        : "create a new user file",
                "remove"     : "remove existing user file",
                "passphrase" : "change user passphrase",
                "merge"      : "merges two user files",
                "clean"      : "clean up a user file",
                "add"        : "add a password entry",
                "delete"     : "remove a password entry",
                "update"     : "update a password entry",
                "revert"     : "revert an entry update",
                "get"        : "derive entry password"}

    parsers = {}
    for cmd in commands.keys():
        parsers[cmd] = subparsers.add_parser(cmd, help = commands[cmd])

        parsers[cmd].add_argument("user")

        if cmd in ["add", "delete", "update", "revert", "get"]:
            parsers[cmd].add_argument("service")
            parsers[cmd].add_argument("identifier")

        if cmd == "add": # the "add" argument has format arguments
            parsers[cmd].add_argument("-f", "--fmt", nargs = '?',
                                      default = pwfmt.default)
            parsers[cmd].add_argument("-p", "--param", nargs = '?',
                                      default = None, type = int)

        if cmd == "merge": # the "merge" argument takes two user files
            parsers[cmd].add_argument("source")

    arg = master.parse_args()
    cmd = arg.command

    try:
        if cmd == "new" or cmd == "passphrase":
            f = Manager(arg.user, cmd == "passphrase")
                
            try:
                passphrase = getpass("New passphrase: ")
                confirm    = getpass("Please confirm: ")
            except:
                print("") # for presentation
                return

            if passphrase != confirm:
                print("Passphrases do not match.")
            else:
                f.ChangePassphrase(passphrase)
                f.Finish()

        elif cmd == "update" or cmd == "revert" or cmd == "delete":
            f = Manager(arg.user, True)
            if cmd == "update":
                if not f.Update(arg.service, arg.identifier):
                    print("Entry does not exist.")

            if cmd == "revert":
                if not f.Revert(arg.service, arg.identifier):
                    if f.Exists(arg.service, arg.identifier):
                        print("Entry has not been updated - cannot revert.")
                    else:
                        print("Entry does not exist.")

            if cmd == "delete":
                if not f.Delete(arg.service, arg.identifier):
                    print("Entry does not exist.")

            f.Finish()

        elif cmd == "add":
            f = Manager(arg.user, True)

            if not f.Add(arg.service, arg.identifier, arg.fmt, arg.param):
                print("Entry already exists.")

            f.Finish()

        elif cmd == "clean":
            f = Manager(arg.user, True)
            f.Finish()

        elif cmd == "remove":
            f = Manager(arg.user, True)

            try:
                p = input("Remove user '" + arg.user + "'? Y/n: ")
            except:
                print("")
                p = "n"

            if p != "Y":
                print("User removal aborted.")
            else:
                f.RemoveUser()

        elif cmd == "get":
            f = Manager(arg.user, True)
            if not f.Exists(arg.service, arg.identifier):
                print("Entry does not exist.")
            else:
                try:
                    passphrase = getpass("Passphrase: ")
                except:
                    print("")
                    return

                pw = f.GetPassword(passphrase, arg.service, arg.identifier)
                if not pw:
                    print("Entry does not exist.") # should not happen
                else:
                    print("Password  : " + pw)

        elif cmd == "merge":
            dst = Manager(arg.user, True)
            src = Manager(arg.source, True)
            addCount = 0

            # This is a conservative merge - we pull every entry from "src"
            # which isn't in "dst". No entry is deleted from either file.
            for entry in src.Entries():
                if not dst.Exists(entry["service"], entry["identifier"]):
                    dst.Entries().append(entry)
                    addCount += 1

            dst.Finish()

            if addCount == 0:
                print("No entries merged.")
            else:
                msg = "Merged {0} entries ({1} -> {2})."
                print(msg.format(addCount, arg.source, arg.user))

        else:
            print("Command not recognized.")

    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()
