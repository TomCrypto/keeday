# Contains password formatting definitions, feel free to add more...
# Each format is _required_ to provide entropy estimations!

from base64 import urlsafe_b64encode
from binascii import hexlify

# The default format
default = 'base64'

# This simply prints out the hexadecimal representation of the derived key and
# truncates it to obtain the desired password length.

# Examples:
# e666a685e4886b9
# 29fd212d9919a18

# Parameter limits and entropy measure:
# 0 < length <= 128
# entropy = length * 4 bits
def hexadecimal(raw, length):
    if length is None: length = 25
    return hexlify(raw).decode("utf-8")[:int(length)] 

# Same as the hexadecimal format, except using URL-safe Base64 encoding scheme
# and truncating from the right, to keep the padding symbols (==).

# Examples:
# ncj3qNyuEUDYQ==
# _x4ncp9k5jf_Q==

# Parameter limits and entropy measure:
# 0 < length <= 80
# entropy = length * 24 / 4 bits   (approximate)
def base64(raw, length):
    if length is None: length = 25
    password = urlsafe_b64encode(raw).decode("utf-8")
    return password[len(password) - int(length):]

# Flavour Star Trek style authorization code, the parameter indicates how many
# words to use, randomly selected from a selection of words and numbers.

# Examples:
# Picard-Delta-Lambda-5-5
# LaForge-Sigma-Theta-1-Omicron-5-4
# Data-Beta-Gamma-6-5

# Parameter limits and entropy measure:
# 4 < count <= 64 (could be higher with more efficient sampling, but ehh) 
# entropy = 15.77 + 4.169 * (count - 4) bits

# Additional notes: if you want to play with the mappings, their size MUST be
# a power of two, otherwise naively doing raw[t] % size is INVALID.
def startrek(raw, count):
    if count is None: count = 8

    # Mappings, which includes 0-9, greek alphabet words and names. I excluded
    # phonetically similar words, to facilitate remembering the passphrases, I
    # also tried to select an aesthetically pleasing alphanumeric balance...
    letters = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Theta', 
               'Theta', 'Kappa', 'Lambda', 'Omicron', 'Sigma', 'Omega']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    names = ['Picard', 'Riker', 'Janeway', 'Worf', 'Tuvok', 'Data',
             'LaForge', 'Troi'] # order is irrelevant

    words = [names[raw[0] % len(names)]] # name first

    for t in range(1, int(count)):
        # Increase the proportion of numbers towards the end
        n = min(int(count) - 1 - t, 3)

        # Note the parametric mapping always adds up to 256 elements
        mapping = letters * (5 * n + 3) + numbers * (22 - 6 * n)
        words.append(mapping[raw[t] % len(mapping)])
        
    return '-'.join(words)
