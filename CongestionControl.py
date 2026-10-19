class CongestionControl:
    def __init__(self, MSS: int):
        self.current_state = "slow_start"
        self.mss = MSS
        self.cwnd = 1 * self.mss
        self.ssthresh = None


    # tamaño de la ventana en bytes
    def get_cwnd(self):
        return int(self.cwnd)


    # cantidad de MSS completos en cwnd
    def get_MSS_in_cwnd(self):
        return int(self.cwnd // self.mss)


    # maneja los cambios en cwnd con la recepción de acks según el estado actual
    def event_ack_received(self):
        if self.current_state == "slow_start":
            self.cwnd += 1 * self.mss

            # verificamos si cambio la condición de slow star
            if self.ssthresh != None and self.cwnd >= self.ssthresh:
                self.current_state = "congestion_avoidance"

        elif self.current_state == "congestion_avoidance":
            # esto considerando que MSS != 0
            self.cwnd += self.mss / self.get_MSS_in_cwnd()


    def event_timeout(self):
        self.ssthresh = int(self.cwnd / 2)
        self.cwnd = 1 * self.mss

        # si hay timeout volvemos a slow start
        self.current_state = "slow_start"


    def is_state_slow_start(self):
        if self.current_state == "slow_start":
            return True
        else:
            return False
        

    def is_state_congestion_avoidance(self):
        if self.current_state == "congestion_avoidance":
            return True
        else:
            return False
        

    def get_ssthresh(self):
        return self.ssthresh