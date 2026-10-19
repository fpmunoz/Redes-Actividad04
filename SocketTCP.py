import socket
import random
from CongestionControl import CongestionControl
from slidingWindowCC import SlidingWindowCC
from socketUDP import SocketUDP

class SocketTCP:
    DEBUG = True

    # consideramos SEQ, SYN, ACK y FIN
    HEADER_SIZE = 4

    def __init__(self):
        # socket no orientado a conexión
        self.udp_socket = SocketUDP()

        # direcciones (ip, puerto)
        self.address_dest = None
        self.address_local = None

        # proximo numero de la secuencia y el que se espera recibir para stop & wait
        self.seq_num_prox = 0
        self.seq_num_recv = 0

        self.timeout = 0.5
        self.max_package = 16

        # datos ya recibidos de la red pero aun no entregados a la aplicacion
        self.recv_buffer = bytearray()
        self.bytes_pend = 0

        self.package_pend = None

        # estados de la conexion
        self.is_connected = False
        self.is_closed = False

        # congestion control
        self.congestion_controller = CongestionControl(MSS=8)
        self.congestion_controller_on = False

        self.number_of_sent_segments = 0


    def bugs(self, msg: str):
        if  self.DEBUG:
            print(f"[DEBUG] {msg}")


    @staticmethod
    def parse_segment(segment_tcp: bytes):
        if len(segment_tcp) < SocketTCP.HEADER_SIZE:
            print("error")
            return None
        else:
            seq = segment_tcp[0]
            syn = segment_tcp[1]
            ack = segment_tcp[2]
            fin = segment_tcp[3]

            package = segment_tcp[4:]

            dicc = {"seq": seq,
                    "syn": syn,
                    "ack": ack,
                    "fin": fin,
                    "data": package}

            return dicc


    @staticmethod
    def create_segment(seq, syn, ack, fin, data=b""):
        # pasamos todo a int para que no haya errores
        header = bytes([int(seq),
                        int(syn),
                        int(ack),
                        int(fin)])

        return header + data


    def stop_timer(self, n=0):  # implementada con ayuda de claude
        if self.udp_socket.timer_list[n] != None:
            self.udp_socket.stop_timer(n)


    def bind(self, address):
        self.udp_socket.bind(address)
        self.address_local = self.udp_socket.socket_udp.getsockname()
        self.bugs(f"Conectado a {self.address_local}")


    def connect(self, address):
        self.address_dest = address
        self.seq_num_prox = random.randint(0, 100)

        # enviamos el mensaje SYN
        syn_msg = self.create_segment(seq=self.seq_num_prox, syn=1, ack=0, fin=0)
        self.udp_socket.settimeout(self.timeout)

        self.bugs(f"3-Way Handshake en {address} con SEQ={self.seq_num_prox}")

        while True:
            self.udp_socket.sendto(syn_msg, self.address_dest)

            try:
                pkt, server_new_address = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                segment = self.parse_segment(pkt)

                # esperamos SYN y ACK del servidor
                if segment and segment["syn"]==1 and segment["ack"]==1:
                    # actualizamos la direccion destino
                    self.address_dest = server_new_address
                    self.seq_num_recv = segment["seq"]

                    self.bugs(f"SYN+ACK recibido con SEQ={segment['seq']}")
                    break
                
            except TimeoutError:
                self.bugs(f"Timeout connect(): Esperando SYN+ACK, reenviando SYN")
                self.stop_timer(0)
                continue

        self.stop_timer(0)

        # enviamos el mensaje ack
        ack_msg = self.create_segment(seq=self.seq_num_prox, syn=0, ack=1, fin=0)
        self.udp_socket.sendto(ack_msg, self.address_dest)

        # siguinete seceuncia
        self.seq_num_prox = (self.seq_num_prox + 1) % 256
        self.seq_num_recv = (self.seq_num_recv + 1) % 256
        self.is_connected = True
        self.udp_socket.settimeout(-1)

        self.bugs(f"3-Way Handshake finalizado en {self.address_dest}, próximo SEQ={self.seq_num_prox}")


    def accept(self):
        self.udp_socket.settimeout(-1)

        while True:
            pkt,client_address = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)

            if segment and segment["syn"]==1 and segment["ack"]==0:
                self.bugs(f"SYN en {client_address} con SEQ={segment['seq']}")
                break
            
        new_socket = SocketTCP()

        if self.address_local:
            ip_local = self.address_local[0] 
        else:
            ip_local= "localhost"  # al revisarlo gemini sugirió agregar este else
                    
        new_socket.bind((ip_local, 0))
        new_address = new_socket.address_local

        new_socket.address_dest = client_address
        new_socket.seq_num_recv = segment["seq"]
        new_socket.seq_num_prox = random.randint(0, 100)

        # se envia SYN y ACK al cliente
        syn_ack_msg = self.create_segment(seq=new_socket.seq_num_prox, syn=1, ack=1, fin=0)
        new_socket.udp_socket.settimeout(new_socket.timeout)

        while True:
            new_socket.udp_socket.sendto(syn_ack_msg, new_socket.address_dest)

            try:                
                ack_pkt, _ = new_socket.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_segment = self.parse_segment(ack_pkt)

                if not ack_segment:
                    continue

                # esperamos el ack del cliente
                if ack_segment["ack"]==1 and ack_segment["syn"]==0:
                    new_socket.stop_timer(0)

                    #siguiente secuencia
                    new_socket.seq_num_prox = (new_socket.seq_num_prox + 1) % 256
                    new_socket.seq_num_recv = (new_socket.seq_num_recv + 1) % 256
                    new_socket.is_connected = True
                    new_socket.udp_socket.settimeout(-1)

                    self.bugs(f"Conexión establecida en {new_address} con {client_address}")
                    return new_socket, new_address

                # si el ack se perdio pero llego un segmento de datos, lo guardamos
                if ack_segment["ack"]==0 and ack_segment["syn"]==0:
                    self.bugs(f"--Caso Borde: Último ACK se perdió--")
                    new_socket.stop_timer(0)

                    #siguiente secuencia
                    new_socket.seq_num_prox = (new_socket.seq_num_prox + 1) % 256
                    new_socket.seq_num_recv = (new_socket.seq_num_recv + 1) % 256
                    new_socket.is_connected = True
                    new_socket.udp_socket.settimeout(-1)

                    new_socket.package_pend = ack_segment
                    return new_socket, new_address
                
            except TimeoutError:
                self.bugs(f"Timeout accept(): Esperando ACK, reenviando SYN+ACK")
                new_socket.stop_timer(0)
                continue


    def send_aux(self, data: bytes):  # funcion construida con ayuda de gemini
        self.udp_socket.settimeout(self.timeout)
        segment = self.create_segment(seq=self.seq_num_prox, syn=0, ack=0, fin=0, data=data)

        while True:
            self.udp_socket.sendto(segment, self.address_dest)

            try:
                ack_msg, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_segment = self.parse_segment(ack_msg)

                if not ack_segment:
                    continue
                
                # esperamos ACK de nuestro seq
                if (ack_segment["ack"]==1 and ack_segment["syn"]==0 and ack_segment["fin"]==0 and ack_segment["seq"]==self.seq_num_prox):
                    self.bugs(f"ACK recibido con SEQ={self.seq_num_prox}")
                    self.stop_timer(0)

                    # avanza la secuencia
                    self.seq_num_prox = (self.seq_num_prox + 1) % 256
                    break
            except TimeoutError:
                self.bugs(f"Timeout: Esperando ACK={self.seq_num_prox} y reenviando")
                self.stop_timer(0)
                continue


    def send_using_stop_and_wait(self, msg: bytes):
        # enviamos el segemento inicial con el largo
        length_bytes = str(len(msg)).encode()
        self.bugs("Iniciando envío Stop & Wait...")
        self.send_aux(length_bytes)

        # enviamos el resto del mensaje
        for i in range(0, len(msg), self.max_package):
            msg_add = msg[i : i+self.max_package]
            self.send_aux(msg_add)

        self.bugs("Envío finalizado")


    def recv_using_stop_and_wait(self, buff_size: int):
        self.udp_socket.settimeout(-1)

        # si no hay bytes pendiente por entregar, se lee el segemento 
        if self.bytes_pend == 0:
            while True:
                if self.package_pend:
                    segment = self.package_pend
                    self.package_pend = None
                else:
                    pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                    segment = self.parse_segment(pkt)

                if not segment:
                    continue

                if segment["syn"]==1 or segment["fin"]==1:
                    continue

                # enviamos ack
                ack_pkt = self.create_segment(seq=segment["seq"], syn=0, ack=1, fin=0)
                self.udp_socket.sendto(ack_pkt, self.address_dest)

                if segment["seq"] == self.seq_num_recv:
                    self.seq_num_recv = (self.seq_num_recv + 1) % 256
                    self.bytes_pend = int(segment["data"].decode())
                    break

        # bytes que se deben entregar
        bytes_to_read = min(self.bytes_pend, buff_size)

        # recibimos fragmentos y los acumulamos en recv_buffer
        while len(self.recv_buffer) < bytes_to_read:
            pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)

            if not segment:
                continue

            if segment["syn"]==1 or segment["fin"]==1:
                continue

            # enviamos ack
            ack_pkt = self.create_segment(seq=segment["seq"], syn=0, ack=1, fin=0)
            self.udp_socket.sendto(ack_pkt, self.address_dest)

            if segment["seq"] == self.seq_num_recv:
                # extraemos los datos
                self.recv_buffer.extend(segment["data"])
                self.seq_num_recv = (self.seq_num_recv + 1) % 256

        result = bytes(self.recv_buffer[:bytes_to_read])
        self.recv_buffer = self.recv_buffer[bytes_to_read:]

        self.bytes_pend -= len(result)

        return result


    def set_congestion_controller(self, status: bool):
        self.congestion_controller_on = status
        self.bugs(f"Control de congestión fijado en: {status}")


    def window_aux(self, window, base_seq, ack_ready, n):  # mejorado con ayuda de claude
        data = window.get_data(n)

        if data is None:
            return
        
        seq = (base_seq + ack_ready + n) % 256
        seg = self.create_segment(seq=seq, syn=0, ack=0, fin=0, data=data)
        self.udp_socket.sendto(seg, self.address_dest, timer_index=0)
        self.number_of_sent_segments += 1


    def send_using_go_back_n(self, msg: bytes):
        # al estar ocupando el contrl de congestión dividimos el mensaje en 8 bytes
        size_package = self.congestion_controller.mss
        segments = [str(len(msg)).encode()]

        for i in range(0, len(msg), size_package):
            segments.append(msg[i : i + size_package])

        total = len(segments)

        if self.congestion_controller_on:
            window_size = self.congestion_controller.get_MSS_in_cwnd()
        else: 
            window_size = 8

        window = SlidingWindowCC(window_size, segments, self.seq_num_prox)
        base_seq = self.seq_num_prox

        self.udp_socket.settimeout(self.timeout)
        self.udp_socket.set_timer_list_length(1)

        ack_ready = 0  # segementos confirmados
        next_seg = 0  # prox a enviar
        sent_max = 0
        
        self.bugs(f"Iniciando envío con Go Back-N, tamaño inicial de la ventana {window_size}...")

        while ack_ready < total:
            while next_seg < (ack_ready + window.window_size) and next_seg < total:
                self.window_aux(window, base_seq, ack_ready, next_seg-ack_ready)
                next_seg += 1
                sent_max = max(sent_max, next_seg)

            if next_seg > ack_ready and self.udp_socket.timer_list[0] is None:
                self.window_aux(window, base_seq, ack_ready, 0)

            try:
                pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_seg = self.parse_segment(pkt)

                if not ack_seg:
                    continue

                if ack_seg["ack"]==1 and ack_seg["syn"]==0 and ack_seg["fin"]==0:
                    steps = ((ack_seg["seq"] - base_seq - ack_ready) % 256) + 1

                    if 1 <= steps <= sent_max - ack_ready:
                        self.bugs(f"ACK recibido con SEQ={ack_seg['seq']} (avanza {steps} segmentos)")
                        self.stop_timer(0)
                        ack_ready += steps
                        steps_left = steps

                        while steps_left > 0:
                            m = min(steps_left, window.window_size)
                            window.move_window(m)
                            steps_left -= m

                        next_seg = max(next_seg, ack_ready)

                        # actualizamos el control de congestión
                        if self.congestion_controller_on:
                            self.congestion_controller.event_ack_received()
                            window.update_window_size(self.congestion_controller.get_MSS_in_cwnd())

                        self.bugs(f"Estado={self.congestion_controller.current_state}; cwnd={self.congestion_controller.get_cwnd()}; ssthresh={self.congestion_controller.get_ssthresh()}; window_size={window.window_size}")
                                                    
            except TimeoutError:
                self.stop_timer(0)

                if self.congestion_controller_on:
                    self.congestion_controller.event_timeout()
                    window.update_window_size(self.congestion_controller.get_MSS_in_cwnd())

                next_seg = ack_ready
                self.bugs(f"Timeout: Reenviando ventana, window_size={window.window_size}")

        self.seq_num_prox = (base_seq + total) % 256
        self.bugs(f"Envio finalizado, próximo SEQ={self.seq_num_prox}")


    def recv_using_go_back_n(self, buff_size: int):
        self.udp_socket.settimeout(-1)

        if self.bytes_pend == 0:
            while True:
                if self.package_pend:
                    segment = self.package_pend
                    self.package_pend = None
                else:
                    pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                    segment = self.parse_segment(pkt)

                if not segment:
                    continue
                if segment["syn"] == 1 or segment["fin"] == 1:
                    continue

                if segment["seq"] == self.seq_num_recv:
                    ack_pkt = self.create_segment(seq=segment["seq"], syn=0, ack=1, fin=0)
                    self.udp_socket.sendto(ack_pkt, self.address_dest)

                    self.seq_num_recv = (self.seq_num_recv + 1) % 256
                    self.bytes_pend = int(segment["data"].decode())
                    break
                else:
                    last_ack = (self.seq_num_recv - 1) % 256
                    ack_pkt = self.create_segment(seq=last_ack, syn=0, ack=1, fin=0)
                    self.udp_socket.sendto(ack_pkt, self.address_dest)

        # bytes que se deben entregar
        bytes_to_read = min(self.bytes_pend, buff_size)
        
        # recibimos fragmentos y los acumulamos en recv_buffer
        while len(self.recv_buffer) < bytes_to_read:
            pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)
        
            if not segment:
                continue
        
            if segment["syn"]==1 or segment["fin"]==1:
                continue

            if segment["seq"] == self.seq_num_recv:
                self.recv_buffer.extend(segment["data"])
                ack_pkt = self.create_segment(seq=segment["seq"], syn=0, ack=1, fin=0)

                self.udp_socket.sendto(ack_pkt, self.address_dest)
                self.seq_num_recv = (self.seq_num_recv + 1) % 256
            else:
                last_ack = (self.seq_num_recv - 1) % 256
                ack_pkt = self.create_segment(seq=last_ack, syn=0, ack=1, fin=0)
                self.udp_socket.sendto(ack_pkt, self.address_dest)

        result = bytes(self.recv_buffer[:bytes_to_read])
        self.recv_buffer = self.recv_buffer[bytes_to_read:]
        self.bytes_pend -= len(result)

        return result


    def send(self, msg: bytes, mode="stop_and_wait"):
         if mode == "stop_and_wait":
             self.send_using_stop_and_wait(msg)
         elif mode == "go_back_n":
             self.send_using_go_back_n(msg)


    def recv(self, buff_size: int, mode="stop_and_wait"):
        if mode == "stop_and_wait":
            return self.recv_using_stop_and_wait(buff_size) 
        elif mode == "go_back_n":
            return self.recv_using_go_back_n(buff_size)         


    def close(self):
        if self.is_closed:
            return

        self.udp_socket.settimeout(self.timeout)
        fin_segment = self.create_segment(seq=self.seq_num_prox, syn=0, ack=0, fin=1)

        timeout_count = 0
        success = False

        self.bugs("Iniciando close()")

        while timeout_count < 3:
            self.udp_socket.sendto(fin_segment, self.address_dest)

            try:
                pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                segment = self.parse_segment(pkt)

                if not segment:
                    continue

                # si respondieron con fin y ack
                if segment["fin"]==1 and segment["ack"]==1:
                    self.seq_num_recv = segment["seq"]
                    self.seq_num_prox = (self.seq_num_prox + 1) % 256

                    success = True
                    break
                
            except TimeoutError:
                self.bugs(f"Timeout close(): Esperando FIN+ACK")
                self.stop_timer(0)
                timeout_count += 1

        self.stop_timer(0)
        self.udp_socket.settimeout(-1)

        if success:
                ack_fin_msg = self.create_segment(seq=self.seq_num_prox, syn=0, ack=1, fin=0)

                for _ in range(3):
                    self.udp_socket.sendto(ack_fin_msg, self.address_dest)

        self.udp_socket.close()
        self.is_connected = False
        self.is_closed = True
        print("Host A: Conexión cerrada\n")


    def recv_close(self):
        if self.is_closed:
            return

        self.udp_socket.settimeout(-1)

        while True:
            pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)

            if not segment:
                continue

            if segment["fin"] == 1:
                self.seq_num_recv = segment["seq"]
                break

            if segment["syn"] == 0 and segment["ack"] == 0: 
                last_ack = (self.seq_num_recv - 1) % 256
                ack_pkt = self.create_segment(seq=last_ack, syn=0, ack=1, fin=0)
                self.udp_socket.sendto(ack_pkt, self.address_dest)

        self.seq_num_recv = (self.seq_num_recv + 1) % 256
        
        ack_fin_msg = self.create_segment(seq=self.seq_num_prox, syn=0, ack=1, fin=1)
        self.udp_socket.settimeout(self.timeout)

        timeout_count = 0
        self.bugs("FIN+ACK en recv_close()")

        while timeout_count < 3:
            self.udp_socket.sendto(ack_fin_msg, self.address_dest)

            try:
                ack_msg, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_segment = self.parse_segment(ack_msg)

                if not ack_segment:
                    continue

                if ack_segment["ack"]==1 and ack_segment["fin"]==0:
                    break

            except TimeoutError:
                self.bugs("Timeout recv_close(): Esperando ACK")
                self.stop_timer(0)
                timeout_count += 1         

        self.stop_timer(0)
        self.udp_socket.settimeout(-1)
        
        self.udp_socket.close()
        self.is_connected = False
        self.is_closed = True
        print("Host B: Conexión cerrada\n")