# BLE socket that takes control over the BLE connection completely
# Uses Bluez on Linux
#
# Code adapted from Scapy BluetoothUserSocket here:
#     https://github.com/secdev/scapy/blob/master/scapy/layers/bluetooth.py
#



import ctypes
import socket
import struct
import select
from ctypes import sizeof
from fcntl import ioctl
from time import sleep

MTU = 1024

HCI_CHANNEL_RAW = 0
HCI_CHANNEL_USER = 1
HCI_CHANNEL_MONITOR = 2
HCI_CHANNEL_CONTROL = 3
HCI_CHANNEL_LOGGING = 4

###########
# Sockets #
###########

class BluetoothSocketError(BaseException):
    pass

class BluetoothCommandError(BaseException):
    pass

class sockaddr_hci(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("hci_dev", ctypes.c_ushort),
        ("hci_channel", ctypes.c_ushort),
    ]
  

def hci_down(device):
    HCIDEVUP   = 0x400448c9  
    HCIDEVDOWN = 0x400448ca  

    # Down device
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.bind((device,))
    ioctl(sock.fileno(), HCIDEVDOWN, device)
    sock.close()
  
class BTUserSocket():
    def __init__(self, adapter_index):
  
        self._closed = False      
        self._socket = None
        self._hci_fd = None
        
        # First ensure the hci device is 'down' to stop Bluez owning it
        hci_down(adapter_index)
        
        # Then create our own USER CHANNEL socket using libc functions and ctypes (from scapy)
        sock_address = sockaddr_hci()
        sock_address.sin_family = socket.AF_BLUETOOTH
        sock_address.hci_dev = adapter_index
        sock_address.hci_channel = HCI_CHANNEL_USER
        
        socket_domain=socket.AF_BLUETOOTH
        socket_type=socket.SOCK_RAW
        socket_protocol=socket.BTPROTO_HCI
        
        sockaddr_hcip = ctypes.POINTER(sockaddr_hci)
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")

        socket_c = libc.socket
        socket_c.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
        socket_c.restype = ctypes.c_int

        bind = libc.bind
        bind.argtypes = (ctypes.c_int,
                         ctypes.POINTER(sockaddr_hci),
                         ctypes.c_int)
        bind.restype = ctypes.c_int

        # Socket
        s = socket_c(socket_domain, socket_type, socket_protocol)
        if s < 0:
            raise BluetoothSocketError(
                f"Unable to open socket")

        # Bind
        r = bind(s, sockaddr_hcip(sock_address), sizeof(sock_address))
        if r != 0:
            raise BluetoothSocketError("Unable to bind socket")

        self._hci_fd = s
        self._socket = socket.fromfd(s, socket_domain, socket_type, socket_protocol)

    def close(self):
        if self._closed:
            return

        # Properly close socket so we can free the device
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")

        close = libc.close
        close.restype = ctypes.c_int
 
        self._closed = True
       
       
        # close both sockets because fromfd duplicates the fd
        close(self._socket.fileno())
        close(self._hci_fd)

    
    def readable(self, timeout=0):
        (ins, _, _) = select.select([self._socket], [], [], timeout)
        return len(ins) > 0
 
    def send_raw(self, data):
    	self._socket.send(data)
  
    def receive_raw(self, x = MTU):
        return self._socket.recv(x)
    
 
###
    def send_command(self, cmd):
        opcode = cmd.opcode
        self._socket.send(bytes(cmd))
        while True:
            r = self._socket.recv(MTU)
            if r.type == 0x04 and r.code == 0xe and r.opcode == opcode:
                if r.status != 0:
                    raise BluetoothCommandError("Command %x failed with %x" % (opcode, r.status))  # noqa: E501
                return r
###                


