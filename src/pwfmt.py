# Contains password formatting definitions, feel free to add more...
# Each format is _required_ to provide entropy estimations!

# The definitions should follow this template:
#
# class FormatName:
#     @staticmethod
#     def default():
#         # return a sensible default parameter
#
#     @staticmethod
#     def validate(param):
#         # return True if valid parameter, False otherwise
#
#     @staticmethod
#     def entropy(param):
#         # return worst-case entropy of password with parameter param
#
#
#     @staticmethod
#     def format(raw, param):
#         # return the formatted form of "raw" (512-bit pseudorandom buffer)
#         # using the parameter param, as a human-readable string.

 #############################################################################
 #############################################################################

from base64 import urlsafe_b64encode
from binascii import hexlify

# The default format
default = 'Base64'

 #############################################################################
 #############################################################################

# This simply prints out the hexadecimal representation of the derived key and
# truncates it to obtain the desired password length.

# Examples:
# e666a685e4886b9
# 29fd212d9919a18

# Parameter limits and entropy measure:
# 1 <= length <= 128
# entropy = length * 4 bits
class Hexadecimal:
    @staticmethod
    def default():
        return 25

    @staticmethod
    def validate(length):
        try:
            return 1 <= length <= 128
        except:
            return False

    @staticmethod
    def entropy(length):
        return 4 * length

    @staticmethod
    def format(raw, length):
        return hexlify(raw).decode("utf-8")[:length]

 #############################################################################
 #############################################################################

# Same as the hexadecimal format, except using URL-safe Base64 encoding scheme
# and truncating from the right, to keep the padding symbols (==).

# Examples:
# ncj3qNyuEUDYQ==
# _x4ncp9k5jf_Q==

# Parameter limits and entropy measure:
# 2 < length <= 80
# entropy = (length - 2) * 6 bits   (approximate)

class Base64:
    @staticmethod
    def default():
        return 25

    @staticmethod
    def validate(length):
        try:
            return 2 < length <= 80
        except:
            return False

    @staticmethod
    def entropy(length):
        return (length - 2) * 6

    @staticmethod
    def format(raw, length):
        password = urlsafe_b64encode(raw).decode("utf-8")
        return password[len(password) - length:]

 #############################################################################
 #############################################################################

# Flavour Star Trek style authorization code, the parameter indicates how many
# words to use, randomly selected from a selection of words and numbers.

# Examples:
# Picard-Delta-Lambda-5-5
# LaForge-Sigma-Theta-1-Omicron-5-4
# Data-Beta-Gamma-6-5

# Parameter limits and entropy measure:
# 4 < length <= 64 (could be higher with more efficient sampling, but ehh) 
# entropy = 15.77 + 4.169 * (length - 4) bits

# Additional notes: if you want to play with the mappings, their size MUST be
# a power of two, otherwise naively doing raw[t] % size is INVALID.

class StarTrek:
    @staticmethod
    def default():
        return 8

    @staticmethod
    def validate(length):
        try:
            return 4 < length <= 64
        except:
            return False

    @staticmethod
    def entropy(length):
        return 15.77 + 4.169 * (length - 4)

    @staticmethod
    def format(raw, length):
        # Mappings, which includes numbers 0-9, greek alphabet words/names. I
        # excluded phonetically similar words, to facilitate remembering the
        # passphrases, and tried to choose a pleasing alphanumeric balance
        letters = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Theta', 
                   'Theta', 'Kappa', 'Lambda', 'Omicron', 'Sigma', 'Omega']
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        names = ['Picard', 'Riker', 'Janeway', 'Worf', 'Tuvok', 'Data',
                 'LaForge', 'Troi'] # order is irrelevant

        words = [names[raw[0] % len(names)]] # name first

        for t in range(1, length):
            # Increase the proportion of numbers towards the end
            n = min(length - 1 - t, 3)

            # Note the parametric mapping always adds up to 256 elements
            mapping = letters * (5 * n + 3) + numbers * (22 - 6 * n)
            words.append(mapping[raw[t] % len(mapping)])
            
        return '-'.join(words)

 #############################################################################
 #############################################################################

# Arbitrary length PIN generator. Can always come in handy, I guess.

# Examples:
# 9153
# 484918

# Parameter limits and entropy measure:
# 4 <= length <= 32 (probabilistic sampling with potential for failure) 
# entropy = 3.32 * length bits

# Additional notes: this format can FAIL as the mapping algorithm to go from
# a byte (0..255) to a digit (0..9) is probabilistic. However, even with the
# longest length parameter available the odds of failing are equal to:
# (6 / 256)^32 ~ 6.9 * 10^-53
# So it will almost certainly not happen in practice. However, if the format
# one day enters an infinite loop or raises a mysterious exception, this may
# be why. If so, congratulations, you just won the lottery 6 times in a row.

class PIN:
    @staticmethod
    def default():
        return 6 # This is quite low, though a PIN is not really meant to be
                 # the pinnacle of cryptography, so much as to be convenient

    @staticmethod
    def validate(length):
        try:
            return 4 <= length <= 32
        except:
            return False

    @staticmethod
    def entropy(length):
        return 3.32 * length

    @staticmethod
    def format(raw, length):
        index = 0
        password = ""
        while len(password) != length:
            val = raw[index]
            if val < 250:
                password += str(val // 25) # unbiased 0..249 -> 0..9
            
            index += 1 # If val >= 250, fail and try next byte
            if index > 63: # This path is *EXTREMELY UNLIKELY*
                raise AssertionError("Ran out of entropy!")

        return password
