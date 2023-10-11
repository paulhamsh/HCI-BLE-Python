# BLE library using HCI commands and events
#
# Uses Bluez on Linux
#
# A lot of information from the Bluetooth Specification v5.4
# Also reading the Bumble python source code here:
#     https://github.com/google/bumble
# And the python-hcipy library here:
#     https://github.com/TheBubbleworks/python-hcipy
#

from time import sleep
from btsocket import *

### constants

COMMAND_TIMEOUT = 1
DATA_TIMEOUT = 10

#gap_adv_type =  ['ADV_IND', 'ADV_DIRECT_IND', 'ADV_SCAN_IND', 'ADV_NONCONN_IND', 'SCAN_RSP']
#gap_addr_type = ['PUBLIC', 'RANDOM']

HCI_SUCCESS = 0x00

LE_PUBLIC_ADDRESS = 0x00
LE_RANDOM_ADDRESS = 0x01

HCI_COMMAND_PKT = 0x01
HCI_ACLDATA_PKT = 0x02
HCI_EVENT_PKT = 0x04

ATT_CID = 0x0004

SCAN_TYPE_ACTIVE  = 0x01
FILTER_POLICY_NO_WHITELIST = 0x00

cmd_text = "\n<< Command:"
att_text = "\n<< LE Command: "


################################################################
#
# Formatting routines
#
################################################################
def as_addr (byts):
    return ':'.join('{:02x}'.format (a) for a in byts)

def as_hex (byts):
    return ' '.join('{:02x}'.format (a) for a in byts)

def as_printable(byts):
    return ''.join('{:c}'.format(a) if (a >= 32 and a <= 126) else '.' for a in byts) 


################################################################
#
# Data parsing routines
#
################################################################

def to_u16 (byts, ind):
    return byts[ind] | (byts [ind+1] << 8)

def to_u8 (byts, ind):
    return byts[ind]

def to_addr(byts, ind):
    return as_addr(bytes(reversed(byts [ind: ind+6])))

def to_data(byts, ind, length):
    return byts[ind: ind + length]

def to_data_rest(byts, ind):
    return byts[ind:]

def to_bits_u16 (byts, ind, start, num_bits):
    val = to_u16(byts, ind)
    val = val >> start
    mask = (1 << num_bits) - 1
    return val & mask

#def reverse_addr(byts) :
#    return bytes(reversed(byts))

def from_u8(val):
    return bytes ([val])

def from_u16(val):
    v1 = val & 0xff
    v2 = val >> 8
    return bytes([v1]) + bytes([v2])

def from_addr(val):
    return bytes(reversed(bytes.fromhex(val.replace(':', ' '))))

def from_data(val):
    return bytes(val)


################################################################
#
# Make the ACL and HCI command headers
#
################################################################

def make_acl(handle, length):
    header =  from_u8 (0x02)       # hci command prefix for ACL
    header += from_u16(handle)     # hci handle
    header += from_u16(length + 4) # hci packet length
    header += from_u16(length)     # l2cap length
    header += from_u16(ATT_CID)    # channel for ATT - 4 for BLE
    return header

def make_cmd(cmd, length):
    header =  from_u8 (0x01)       # hci command prefix
    header += from_u16(cmd)        # hci command
    header += from_u8 (length)     # hci packet length
    return header

################################################################
#
# Bluetooth class
#
# Contains core class and all command and event handling
#
################################################################

class BluetoothLEConnection:

    def __init__(self, dev_id=0):
        self.handle = 64
        self.user_socket = BTUserSocket(dev_id)

        # ACL packet being constructed
        self.acl_packet = None
        self.acl_length = 0
        self.acl_total_length = 0

        # Last command complete information
        self.command_complete = None
        self.command_status = None

    def __del__(self):
        self.user_socket.close()
        return

    ### helper functions calling BTUserSocket

    def send(self, data):
        print("\n<<", "Data sent: ", as_hex(data))
        self.user_socket.send_raw(data)

    def receive(self):
        data = self.user_socket.receive_raw()
        print("\n>>", "Data received: ", as_hex(data))
        self.on_data(data)
        return data

    def readable(self):
        return self.user_socket.readable()

    def wait_listen(self, timeout = DATA_TIMEOUT):
        quanta = 0.1
        timer = timeout
        while timer > 0:
            timer -= quanta
            while self.readable():
                a = self.receive()
            sleep(quanta)

    def wait_complete(self, command, timeout = DATA_TIMEOUT):
        quanta = 0.1
        timer = timeout
        while timer > 0 and self.command_complete != command:
            timer -= quanta
            while self.readable():
                a = self.receive()
            sleep(quanta)

    def send_command(self, command, packet):
        cmd = make_cmd(command, len(packet)) + packet
        self.send(cmd)
        self.wait_complete(command, COMMAND_TIMEOUT)

    ################################################################
    #
    # Event handling routines
    #
    # Process HCI events and meta-events
    #
    ################################################################

    # 1 = Command Packets
    # 2 = Data Packets for ACL
    # 3 = Data Packets for SCO
    # 4 = Event Packets

    # Handle HCI meta event types

    def on_le_connection_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.65.1 LE Connection Complete (p2235)
        # Event_code = 0x3e
        # HCI_LE_Connection_Complete = 0x01
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     subevent code                                  1 octet
        #     status                                         1 octet
        #     connection_handle                              2 octets
        #     role                                           1 octets
        #     peer_address_type                              1 octet
        #     peer_address                                   6 octets
        #     connection_interval                            2 octets
        #     peripheral_latency                             2 octets
        #     supervision_timeout                            2 octets
        #     central_clock_accuracy                         1 octet
      
        status = to_u8(data, 4)
        handle = to_u16(data, 5)
        address = to_addr(data, 9)
        
        self.handle = handle         # save this for other commands to use
        print("LE Connection Complete")
        print("Status: {:02x} Address: {}".format(status, as_hex(address)))

    def on_le_advertising_report(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.65.2 LE Advertising Report (p2238)
        # Event_code = 0x3e
        # HCI_LE_Advertising_Report = 0x02
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     subevent_code                                  1 octet
        #     num_reports                                    1 octet
        #         event_type[i]                              1 octet
        #         address_type[i]                            1 octet
        #         address[i]                                 6 octets
        #         data_length[i]                             1 octet
        #         data[i]                                    data_length octets
        #         rssi[i]                                    1 octet
        
        # These lines double the report to test for num_reports = 2
        #num_reports = to_u8       (data, 4)
        #reports =     to_data_rest(data, 5)
        #data = data[0:4] + from_u8(2) + reports + reports

        num_reports = to_u8       (data, 4)
        reports =     to_data_rest(data, 5)                  # the actual 'reports'
        
        report_offset = 0                                    # start of this entry in 'reports'
        for rep in range(0, num_reports):
            address =     to_addr (reports, report_offset+2)
            data_len =    to_u8   (reports, report_offset+8)
            report_data = to_data (reports, report_offset+9, data_len)
            rssi =        to_u8   (reports, report_offset+9 + data_len)
            
            print("Address: {}      RSSI: {}".format(address, rssi))
            i = 0
            while i < data_len:
                entry_len = to_u8(report_data, i) 
                if entry_len > 0:
                    typ = to_u8  (report_data, i+1)
                    dat = to_data(report_data, i+2, entry_len-1)
                    print("Length: {:3} Type: {:02x}  Data: {}      {}".format(entry_len, typ, as_hex(dat), as_printable(dat)))
                    i += entry_len
                i += 1
            report_offset += data_len+10                     # move on to next entry
                  
    def on_le_connection_update_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.65.3 LE Connection Update Complete (p2240)
        # Event_code = 0x3e
        # HCI_LE_Connection_Update_Complete = 0x03
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     subevent code                                  1 octet
        #     status                                         1 octet
        #     connection_handle                              2 octets
        #     connection_interval                            2 octets
        #     peripheral_latency                             2 octets
        #     supervision_timeout                            2 octets

        status =   to_u8(data, 4)
        handle =   to_u16(data, 5)
        interval = to_u16(data, 7)
        latency = to_u16(data, 9)
        timeout =  to_u16(data, 11)
        
        print("LE Connection Update Complete")
        print("Handle: {:04x} Status: {02x}".format(handle, status))
        
        #self.handle = handle         # save this for other commands to use

        # Should respond with 020001 ???

    def on_le_read_remote_features_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.65.4 LE Meta event (p2242)
        # Event_code = 0x3e
        # HCI_LE_Read_Remote_Features_Complete = 0x04
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     subevent_code                                  1 octet
        #     status                                         1 octet
        #     connection_handle                              2 octets
        #     le features                                    8 octets      # need to update templates for this!!

        print("Read Remote Features Complete")
        
        handle = to_u16(data, 5)
        features = to_data_rest(data, 7)
        
        print("Handle: {} Features {}".format(handle, as_hex(features)))

    def on_hci_meta_event(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.65 LE Meta event (p2235)
        # Event_code = 0x3e
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     subevent_code                                  1 octet
        #     data                                           n octets

        subevent_code = to_u8(data, 3)
        print("Event: LE Meta event: ", hex(subevent_code))
        if   subevent_code == 0x01:                 # LE Connection Complete
            self.on_le_connection_complete(data)
        elif subevent_code == 0x03:                 # LE Connection Update Complete
            self.on_le_update_complete(data)
        elif subevent_code == 0x02:                 # LE Advertising Report
            self.on_le_advertising_report(data)
        elif subevent_code == 0x04:                 # LE Read Remove Features Complete
            self.on_le_read_remote_features_complete(data)
        else:
            print("LE Meta Event: Unhandled:", hex(subevent_code))

    def on_hci_event_disconnect_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.5 HCI_Disconnection_Complete (p2163)
        # HCI_Disconnection_Complete = 0x05
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     status                                         1 octet
        #     connection_handle                              2 octets
        #     reason                                         1 octet


        print("Event: HCI Disconnection Complete")

        status = to_u8  (data, 3)
        handle = to_u16 (data, 4)
        reason = to_u8  (data, 6)

    def on_hci_event_command_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.14 HCI Command Complete (p2177)
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     num_hci_command_packets                        1 octet
        #     command_opcode                                 2 octets
        #     return_parameters                              n octets
        
        # First return_parameters field is usually
        #     status                                         1 octet

        print("Event: HCI Command Complete")
        cmd =    to_u16 (data, 4)
        status = to_u8  (data, 6)
        
        status_text = "Success" if status == HCI_SUCCESS else "Failure"
        self.command_complete = cmd
        self.command_status =   status

        if   cmd == 0x200B:                                       # LE Set Scan Paramaters
            print('LE Scan Parameters Set:',status_text);
        elif cmd == 0x200c:                                       # LE Set Scan Enable
            print('LE Scan Enable Set:', status_text)
        elif cmd == 0x2006:                                       # LE Set Advertising Parameters
            print('LE Advertising Parameters Set:', status_text)
        elif cmd == 0x2008:                                       # LE Set Advertising Data
            print('LE Advertising Data Set:', status_text)
        elif cmd == 0x2009:                                       # LE Set Scan Repsonse Data
            print('LE Scan Response Data Set:', status_text)
        elif cmd == 0x200a:                                       # LE Set Advertise Enable
            print('LE Advertise Enable Set:', status_text)
        else:
            print('LE Unknown Command:', hex(cmd), status_text)

    def on_hci_event_command_status(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.15 HCI_Command_Status (p2179)
        # HCI_Command_Status = 0x0f
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     status                                         1 octet
        #     num_hci_command_packets                        1 octet
        #     command_opcode                                 2 octets

        print("Event: HCI Command Status")
        status = to_u8  (data, 3)
        opcode = to_u16 (data, 5)

        print("Opcode: {:02x} status: {:02x}".format(opcode, status))

    def on_hci_number_of_completed_packets(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.19 HCI Number Of Completed Packets (p2184)
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     num_handles                                    1 octet
        #     connection handle[i]                           2n octets
        #     num completed packets[i]                       2n octets

        print("Event: HCI Number Of Completed Packets")

    def on_hci_event_packet(self, data):
        # Specification v5.4  Vol 4 Part E 5.4.4 HCI Event Packet (p1804)
        #     [packet_type                                   1 octet]
        #     event_code                                     1 octet
        #     parameter_length                               1 octet
        #     parameters                                     n octets

        event = to_u8(data, 1)         
        print("HCI Event Packet:", hex(event))

        if   event == 0x0f:                                   # Command Status
            self.on_hci_event_command_status(data)
        elif event == 0x05:                                   # Disconnection Complete
            self.on_hci_event_disconnect_complete(data)
        elif event == 0x3e:                                   # LE Meta Event
            self.on_hci_meta_event(data)
        elif event == 0x0e:                                   # Command complete
            self.on_hci_event_command_complete(data)
        elif event == 0x13:                                   # Number of Completed Packets
            self.on_hci_number_of_completed_packets(data)
        else:
            print("HCI Event: Unhandled", hex(event))

    def on_acl_data_packet(self, data):
        # Specification v5.4  Vol 4 Part E 5.4.2 HCI ACL Packet (p1801)
        #     [packet_type                                  1 octet]
        #     handle (BC[2] PB[2] handle[12])               2 octets
        #     packet length                                 2 octets
        #     data_length                                   2 octets
        #     channel                                       2 octets
        #     data                                          n octets

        print("ACL Packet")

        handle = to_bits_u16(data, 1, 0, 12)
        pb =     to_bits_u16(data, 1, 12, 2)
        bc =     to_bits_u16(data, 1, 14, 2)
        length = to_u16(data, 3)  #di["packet length"]
 
        full_packet = False
        print('ACL header: handle: {}  bc: {}  pb: {}'.format(handle, bc, pb))

        if pb & 0x01 == 0:
            size =     to_u16(data, 5)
            channel =  to_u16(data, 7)
            acl_data = to_data_rest(data, 9)
            full_packet = length - size == 4

            print("Channel: {} Length: {} Data size: {} Full packet? {}".format(channel, length, size, full_packet))
            print("ACL data:  ", as_hex(acl_data))

            if not full_packet:                                  # This is not a full packet, so start to store the acl_packet
                self.acl_total_length = size
                self.acl_packet =       acl_data

        if pb & 0x01 == 1:
            print("ACL Packet Continuation")
            acl_data = to_data_rest(data, 5)
            self.acl_packet += acl_data
            print("ACL data:  ", as_hex(acl_data))
            if len(self.acl_packet) == self.acl_total_length:    # This was the last continuation packet
                full_packet = True
                print("ACL Packet Final")
                print("Full ACL data: ", as_hex(self.acl_packet))
                
        if full_packet:
            pass                # Do something now we have the full packet - self.acl_packet
            

    # HCI packet received handler

    def on_data(self, data):
        # Specification v5.4  Vol 4 Part E 5.4.4 HCI Event Packet (p1804)
        # Specification v5.4  Vol 4 Part E 5.4.2 HCI ACL Packet (p1801)
        #
        #     packet_type                                    1 octet

        packet_type = to_u8(data, 0)
        print("Packet type:", packet_type)

        self.command_complete = None               # set to None and changed by Command Complete event
        self.command_status = None

        if   packet_type == 0x04:                  # event packet
            self.on_hci_event_packet(data)
        elif packet_type == 0x02:                  # ACL data packet
            self.on_acl_data_packet(data)
        else:
            print("Unhandled packet type", packet_type)

    ################################################################
    #
    # Command handling routines
    #
    # Process HCI commands
    #
    ################################################################


    def do_set_advertising_parameters(self, adv_type=0x00, own_addr_type=0x00,
                                      peer_addr='11:22:33:44:55:66', peer_addr_type=0x00,
                                      min_interval=0x00a0, max_interval=0x00a0, adv_channel_map=0x07,
                                      adv_filter_policy=0x00):
        # Specification v5.4  Vol 4 Part E 7.8.5 LE Set Advertising Parameters (p2350)
        # Opcode 0x2006
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octets]
        #     advertising interval min                      2 octets
        #     advertising interval max                      2 octets
        #     advertising type                              1 octet
        #     own address type                              1 octet
        #     peer address type                             1 octet
        #     peer address                                  6 octets
        #     advertising channel map                       1 octet
        #     advertising filter policy                     1 octet
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x2006

        print(cmd_text, "LE Set Advertising Parameters")
        
        packet =  from_u16  (min_interval)
        packet += from_u16  (max_interval)
        packet += from_u8   (adv_type)
        packet += from_u8   (own_addr_type)
        packet += from_u8   (peer_addr_type)
        packet += from_addr (peer_addr)
        packet += from_u8   (adv_channel_map)
        packet += from_u8   (adv_filter_policy)
        self.send_command(0x2006, packet)

    def do_set_advertising_data(self, data):
        # Specification v5.4  Vol 4 Part E 7.8.7 LE Set Advertising Data (p2355)
        # Opcode 0x2008
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octets]
        #     advertising data length                       1 octet
        #     advertising data                              31 octets
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x2008

        print(cmd_text, "LE Set Advertising Data")

        pad = bytes(b'\x00' * (31-len(data)))
        packet = from_u8 (len(data))
        packet +=         data
        packet +=         pad
        self.send_command(0x2008, packet)

    def do_set_scan_response_data(self, data):
        # Specification v5.4  Vol 4 Part E 7.8.8 LE Set Scan Response Data (p2357)
        # Opcode 0x2009
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octets]
        #     advertising data length                       1 octet
        #     advertising data                              31 octets
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x2009

        print(cmd_text, "LE Set Scan Response Data")
        pad = bytes(b'\x00' * (31 - len(data)))

        packet =  from_u8 (len(data))
        packet +=         data
        packet +=         pad
        self.send_command(0x2009, packet)

    def do_set_advertise_enable(self, enabled):
        # Specification v5.4  Vol 4 Part E 7.8.9 LE Set Advertising Enable (p2359)
        # Opcode 0x200a
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octets]
        #     advertising enable                            1 octet
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x200a
        #     HCI LE Connection Complete                    0x3e  0x01      (in some cases)

        print(cmd_text, "LE Set Advertising Enable")
        
        packet = from_u8(0x01 if enabled else 0x00)
        self.send_command(0x200a, packet)

    def do_set_scan_parameters(self, scan_type=SCAN_TYPE_ACTIVE, scan_internal=0x0060, scan_window=0x0060,
                               own_addr_type=LE_PUBLIC_ADDRESS, scan_filter_policy=FILTER_POLICY_NO_WHITELIST):
        # Specification v5.4  Vol 4 Part E 7.8.10 LE Set Scan Parameters (p2361)
        # Opcode 0x200b
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octet]
        #     le scan type                                  1 octet
        #     le scan interval                              2 octets
        #     le scan window                                2 octets
        #     own address type                              1 octet
        #     scanning filter policy                        1 octet
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x200b

        print(cmd_text, "LE Set Scan Parameters")
        
        packet =  from_u8  (scan_type)
        packet += from_u16 (scan_internal)
        packet += from_u16 (scan_window)
        packet += from_u8  (own_addr_type)
        packet += from_u8  (scan_filter_policy)
        self.send_command(0x200b, packet)

    def do_set_scan(self, enabled=False, duplicates=False):
        # Specification v5.4  Vol 4 Part E 7.8.11 LE Set Scan Enable (p2364)
        # Opcode 0x200c
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octet]
        #     le scan enable                                1 octet
        #     filter duplicates                             1 octet
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x200c
        #     HCI LE Advertising Report                     0x3e  0x02      (one or more)

        #enable = 0x01 if enabled else 0x00
        #dups   = 0x01 if duplicates else 0x00

        print(cmd_text, "LE Set Scan Enable" if enabled else "LE Set Scan Disable")
        
        packet =  from_u8(0x01 if enabled else 0x00)
        packet += from_u8(0x01 if duplicates else 0x00)        
        self.send_command(0x200c, packet)

    def do_create_connection(self, addr, addr_type, interval=0x0060, window=0x0060, initiator_filter=0x00,
                             own_addr_type= 0x00, min_interval=0x0018, max_interval=0x0028, latency=0x0000,
                             supervision_timeout=0x002a, min_ce_length=0x0000, max_ce_length = 0x0000):
        # Specification v5.4  Vol 4 Part E 7.8.12 LE Create Connection (p2366)
        # Opcode 0x200d
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octet]
        #     le scan interval                              2 octets
        #     le scan window                                2 octets
        #     initiator filter policy                       1 octet
        #     peer address type                             1 octet
        #     peer address                                  6 octets
        #     own address type                              1 octet
        #     connection interval min                       2 octets
        #     connection interval max                       2 octets
        #     max latency                                   2 octets
        #     supervision timeout                           2 octets
        #     min ce length                                 2 octets
        #     max ce length                                 2 octets
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x200d
        #     HCI LE Connection Complete                    0x3e  0x01

        print(cmd_text, "LE Create Connection")
        
        packet =  from_u16 (interval)
        packet += from_u16 (window)
        packet += from_u8  (initiator_filter)
        packet += from_u8  (addr_type)
        packet += from_addr(addr)
        packet += from_u8  (own_addr_type)
        packet += from_u16 (min_interval)
        packet += from_u16 (max_interval)
        packet += from_u16 (latency)
        packet += from_u16 (supervision_timeout)
        packet += from_u16 (min_ce_length)
        packet += from_u16 (max_ce_length)
        self.send_command(0x200d, packet)
        

    def do_add_device_to_accept_list(self, addr, addr_type):
        # Specification v5.4  Vol 4 Part E 7.8.16 LE Add Device To Filter Accept List (p2375)
        # Opcode 0x2011
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octet]
        #     address type                                  1 octet
        #     address                                       6 octets
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x2011


        print(cmd_text, "LE Add Device To Filter Accept List")
        
        packet =  from_u8(addr_type)
        packet += from_addr(addr)
        self.send_command(0x2011, packet)

    def do_read_remote_used_features(self):
        # Specification v5.4  Vol 4 Part E 7.8.21 LE Read Remote Features (p2385)
        # Opcode 0x2016
        #
        #     [packet_type                                  1 octet]
        #     [opcode                                       2 octets]
        #     [packet length                                1 octet]
        #     connection handle                             2 octets
        #
        # Response:
        #     HCI Command Complete                          0x0e  0x2016
        #     HCI LE Read Remote Features Complete          0x3e  0x04  

        print(cmd_text, "LE Read Remote Features")
        
        packet = from_u16(self.handle)
        self.send_command(0x2016, packet)

    #
    # ACL commands
    #
    
    def do_att_exchange_mtu_req(self, mtu_size = 517):
        # Specification v5.4  Vol 3 Part F 3.4.2.1 ATT_EXCHANGE_MTU_REQ (p1416)
        # ATT Opcode 0x02
        #     [packet_type                                  1 octet]
        #     [handle (BC[2] PB[2] handle[12])              2 octets]
        #     [packet length                                2 octets]
        #     [data_length                                  2 octets]
        #     [channel                                      2 octets]
        #     opcode                                        1 octet
        #     client receive mtu size                       2 octets

        print(att_text, "ATT EXCHANGE MTU REQ")

        packet =  from_u8  (0x02)           # ATT opcode ATT_EXCHANGE_MTU_REQ
        packet += from_u16 (mtu_size)       # MTU size requested
        
        cmd = make_acl(self.handle, len(packet)) + packet
        self.send(cmd)


    def do_att_find_information_req(self, start_handle, end_handle):
        # Specification v5.4  Vol 3 Part F 3.4.3.1 ATT_FIND_INFORMATION_REQ (p1418)
        # ATT Opcode 0x04
        #
        #     [packet_type                                  1 octet]
        #     [handle (BC[2] PB[2] handle[12])              2 octets]
        #     [packet length                                2 octets]
        #     [data_length                                  2 octets]
        #     [channel                                      2 octets]
        #     opcode                                        1 octet
        #     starting handle                               2 octets
        #     ending handle                                 2 octets

        print(att_text, "ATT FIND INFORMATION REQ")
        
        packet =  from_u8  (0x04)          # ATT opcode ATT_FIND_INFORMATION_REQ
        packet += from_u16 (start_handle)
        packet += from_u16 (end_handle)

        cmd = make_acl(self.handle, len(packet)) + packet
        self.send(cmd)


    def do_att_read_by_type_req(self, start_handle, end_handle, attribute_type):
        # Specification v5.4  Vol 3 Part F 3.4.4.1 ATT_READ_BY_TYPE_REQ (p1422)
        # ATT Opcode 0x08
        #
        #     [packet_type                                  1 octet]
        #     [handle (BC[2] PB[2] handle[12])              2 octets]
        #     [packet length                                2 octets]
        #     [data_length                                  2 octets]
        #     [channel                                      2 octets]
        #     opcode                                        1 octet
        #     starting handle                               2 octets
        #     ending handle                                 2 octets
        #     attribute type (UUID)                         2 or 16 octets

        print(att_text, "ATT READ BY TYPE REQ")
        
        packet =  from_u8  (0x08)               # ATT opcode ATT_READ_BY_TYPE_REQ
        packet += from_u16 (start_handle)
        packet += from_u16 (end_handle)
        packet += from_u16 (attribute_type)        
               
        cmd = make_acl(self.handle, len(packet)) + packet
        self.send(cmd)


