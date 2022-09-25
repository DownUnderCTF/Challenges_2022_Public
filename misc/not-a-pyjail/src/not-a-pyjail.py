#!/usr/bin/env python3

import subprocess
import sys
import tempfile

print("Welcome to the Python syntax checking service!")
print("The safest code is the code you don't even execute.")
print("Enter your code. Write __EOF__ to end.", flush=True)

code = b"exit(0)\n"
for line in sys.stdin.buffer:
    if line.strip() == b"__EOF__":
        break
    code += line

with tempfile.NamedTemporaryFile() as sandbox:
    sandbox.write(code)
    sandbox.flush()
    pipes = subprocess.Popen(["python3", sandbox.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = pipes.communicate()
    if pipes.returncode == 0:
        print("Syntax OK!") 
    else:
        print("There was an error:")
        print(stderr.decode())
