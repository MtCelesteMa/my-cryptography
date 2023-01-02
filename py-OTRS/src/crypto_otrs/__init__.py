# __init__.py

# Version of the realpython-reader package
__version__ = "1.0.4"

import os
script_dir = os.path.abspath(os.path.dirname(__file__))
lib_path = os.path.join(script_dir, "libring.so")
sha_path = os.path.join(script_dir, "sha2.c")
ring_path = os.path.join(script_dir, "ring.c")

print(lib_path)
if os.path.exists(lib_path) == False:
    print("libring not found, compiling...")
    os.system("clang -fPIC -shared -g -lm -lssl -lcrypto " + sha_path + " " + ring_path + " -o "+lib_path)