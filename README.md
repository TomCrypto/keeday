keeday
==============

Password Derivation Tool
--------------

This is the github repository for keeday, a small Python-based tool to manage strong cryptographically generated passwords. The source is quite self-documenting but has a few comments where needed. Feel free to use it or modify it as you wish, and don't hesitate to notify me of any security issues (no matter how minor) I might have overlooked.

This is mostly an experimental prototype and is not specifically intended for real use, however the default settings are considered to be strong enough for general-purpose usage - if you have a strong passphrase - should you decide to adopt this tool.

The only location this tool will write to is ~/.keeday/ , where ~ is your home directory. The folder will be created, assuming you run the script with appropriate permissions. **Do not run this tool as root under any circumstances, as it does not require elevated privileges.**

The tool's name is based on "key derivation function" (get it? ha ha)
