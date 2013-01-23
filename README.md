keeday
==============

Password Derivation Tool
--------------

This is the github repository for keeday, a small Python-based tool to manage strong and cryptographically generated passwords. The source is quite self-documenting but has a few comments where needed. Feel free to use it or modify it as you wish, and don't hesitate to notify me of any security issues (no matter how minor) I might have overlooked.

This is mostly an experimental prototype and is not specifically intended for real use, however the default settings are considered to be sufficient enough for general-purpose usage - if you have a strong passphrase - should you decide to adopt this tool.

The only location this tool will write to is ~/.keeday/ , where ~ is your home directory. The folder will be created, assuming you run the script with appropriate permissions. **Do not run this tool as root under any circumstances, it doesn't need elevated privileges.**

The Python 3.2 source code is in the src folder, and a man page is available in the man folder.

See README for a short introduction to the tool, the LICENSE is to be read and understood.

The tool's name is based on "key derivation function" (get it? ha ha)
