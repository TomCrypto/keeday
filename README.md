keeday - Password Derivation Tool
=================================

This is the github repository for keeday, a small Python-based tool to manage strong and cryptographically generated passwords. The source code is quite self-documenting but has a few comments where needed. Feel free to use or modify this tool as you see fit, and don't hesitate to notify me of any security issues (no matter how minor) I might have overlooked.

This is mostly an experimental prototype and is not specifically intended for real use, however the default settings are considered to be sufficient enough for general-purpose usage - if you have a strong passphrase, of course - should you decide to adopt this tool.

The only location this tool will write to is ~/.keeday/ , where ~ is your home directory. This folder will be created for you.

Compatibility
-------------

The source code is fully compatible with Python 3.1, Python 3.2 and Python 3.3. Support for Python 2.7 is achievable but I have chosen not to pursue it, at least for the moment. Versions prior to 2.7 are not supported.

Documentation
-------------

See README for a short introduction to the tool, the LICENSE is to be read and understood. A man page is also available.

The tool's name is based on "key derivation function" (get it? ha ha)
