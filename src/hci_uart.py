from machine import UART, Pin
from time import sleep, ticks_ms, ticks_add, ticks_diff

class HCI():
    def __init__(self, adapter_index):
        self.init_nina()
        self.init_uart()
 
    def close(self):
        return

    def init_nina(self):
        _SPIWIFI_SS  = Pin(9, Pin.OUT)
        _NINA_RESETN = Pin(3, Pin.OUT)
        # Start NINA ESP32
        _SPIWIFI_SS.value(0)
        _NINA_RESETN.value(0)
        sleep(0.1)
        _NINA_RESETN.value(1)
        sleep(0.75)

    def init_uart(self):
        self.uart = UART(1, baudrate=115200, tx=8, rx=9, cts=10, rts=11, rxbuf=250, txbuf=250)
        self.uart.flush()
        self.clear_received()          
        
    def clear_received(self):
        while self.uart.any():
            self.uart.read()

    def readable(self, timeout=0):
        return self.uart.any() > 0
 
    def send_raw(self, data):
        self.uart.write(data)
  
    def receive_raw(self):
        deadline = ticks_add(ticks_ms(), 100)
        buffer = b''
        length = 0

        done = False
        packet_type = -1
        packet_length = -1
    
        while not done:
            if self.uart.any():
                byt = self.uart.read(1)
                buffer += byt
                length += 1
    
            if length == 1:
                packet_type = int(buffer[0])
            
            if packet_type > 0:
                if packet_type == 2 and length == 5:
                    packet_length = int(buffer[3]) + 256 * int(buffer[4]) + 5
                if packet_type == 4 and length == 3:
                    packet_length = int(buffer[2]) + 3
         
            if packet_length > 0 and length >= packet_length:
                done = True
            
        # include a timeout in case the data gets misalgined
            if ticks_diff(ticks_ms(), deadline) > 0:
                buffer = b''
                done = True
    
        return buffer        
    
