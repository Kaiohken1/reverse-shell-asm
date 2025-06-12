import socket
import sys
import select

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 4444))
s.listen(5)

print("Listening on 0.0.0.0:4444...")

conn, addr = s.accept()
print(f"Connection from {addr}")

try:
    while True:
        rlist, _, _ = select.select([conn, sys.stdin], [], [])
        
        for ready in rlist:
            if ready == conn:
                # Recevoir les données du client (résultats des commandes)
                data = conn.recv(1024)
                if not data:
                    print("Connection closed")
                    sys.exit(0)
                
                # Afficher les résultats directement
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                
            else:
                # Envoyer une commande au client
                cmd = sys.stdin.readline()
                if cmd.strip():
                    conn.send(cmd.encode())
                
except KeyboardInterrupt:
    print("\nExiting...")
    conn.close()
    s.close()