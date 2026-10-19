import sys
import time 
from SocketTCP import SocketTCP

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cliente.py <ip> <puerto> < archivo", file=sys.stderr)
        sys.exit(1)

    address = (sys.argv[1], int(sys.argv[2]))
    file_msg = sys.stdin.buffer.read()

    # CLIENT
    client_socketTCP = SocketTCP()
    client_socketTCP.set_congestion_controller(True)
    client_socketTCP.timeout = 0.5
    client_socketTCP.connect(address)

    t0 = time.perf_counter()  # idea de claude
    client_socketTCP.send(file_msg, mode="go_back_n")
    t1 = time.perf_counter() - t0

    client_socketTCP.close()

    print(f"tiempo={t1:.3f}s")
    print(f"Mensajes intercambiados: {client_socketTCP.number_of_sent_segments}")
    print(f"Cliente: {len(file_msg)} bytes enviados.\n", file=sys.stderr)
    


if __name__ == "__main__":
    main()