import sys
from SocketTCP import SocketTCP

ADDRESS = ("localhost", 8000)
BUFF_SIZE = 25


def main():
    file_data = sys.stdout.buffer
    sys.stdout = sys.stderr

    # SERVER
    server_socketTCP = SocketTCP()
    server_socketTCP.bind(ADDRESS)
    print(f"Servidor: Escuchando en {ADDRESS}")

    connection_socketTCP, new_address = server_socketTCP.accept()

    total = 0

    while True:
        full_message = connection_socketTCP.recv(BUFF_SIZE, mode="go_back_n")
        file_data.write(full_message)
        total += len(full_message)

        if connection_socketTCP.bytes_pend == 0 and len(connection_socketTCP.recv_buffer) == 0:
            break

    file_data.flush()

    connection_socketTCP.recv_close()
    server_socketTCP.udp_socket.close()

    print(f"Servidor: {total} bytes recibidos.\n")


if __name__ == "__main__":
    main()