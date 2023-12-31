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

gap_adv_type =  ['ADV_IND', 'ADV_DIRECT_IND', 'ADV_SCAN_IND', 'ADV_NONCONN_IND', 'SCAN_RSP']
gap_addr_type = ['PUBLIC', 'RANDOM']

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
# Data parsing routines
#
# Parse data templates into dictionary and from dictionary
#
################################################################

def to_u16 (byts, ind):
    return byts[ind] | (byts [ind+1] << 8)

def to_u8 (byts, ind):
    return byts[ind]

def to_addr(byts, ind):
    return bytes(reversed(byts [ind: ind+6]))

def to_data(byts, ind, length):
    return byts[ind: ind + length]

def reverse_addr(byts) :
    return bytes(reversed(byts))

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

def as_addr (byts):
    return ':'.join('{:02x}'.format (a) for a in byts)

def as_hex (byts):
    return ' '.join('{:02x}'.format (a) for a in byts)

def as_printable(byts):
    return ''.join('{:c}'.format(a) if (a >= 32 and a <= 126) else '.' for a in byts) 

def make_dict(template, data):
    new_dict ={}
    position = 0
    for x in template:
        k =x[0]
        fmt = x[1]

        if fmt == 'counted array':
            templ = x[2]
            arr = []
            data_count = to_u8(data, position)
            position += 1
            for n in range(0, data_count):
                (dat, leng) = make_dict(templ, data[position:])
                position += leng
                arr.append(dat)
            val = arr
        elif fmt == 'bitfield 16':
            templ = x[2]
            val = to_u16(data, position)
            position += 2
            for b in templ:
                key = b[0]
                pos = b[1]
                num_bits = b[2]
                v = val >> pos
                mask = (1 << num_bits) - 1
                new_dict[key] = v & mask
        elif fmt == '1 octet':
            val = to_u8(data, position)
            position += 1
        elif fmt == '2 octets':
            val = to_u16(data, position)
            position += 2
        elif fmt == 'addr':
            val = as_addr(to_addr(data, position))
            position += 6
        elif fmt == 'variable len data':
            data_len = to_u8(data, position)
            position += 1
            val = to_data(data, position, data_len)
            position += data_len
        elif fmt == 'remaining':
            data_len = len(data) - position
            val = to_data(data, position, data_len)
            position += data_len
        new_dict[k] = val
    return new_dict, position


def make_data(template, dict_data):
    nb =b''
    i = 0
    for x in template:
        k =x[0]
        fmt = x[1]
        if fmt == 'counted array':
            templ = x[2]
            nbb=b''
            count = 0
            for n in dict_data[k]:
                nbb += make_data(templ, n)
                count += 1
            le = from_u8(count)
            v = le + nbb
        elif fmt == '1 octet':
            v = from_u8(dict_data[k])
        elif fmt == '2 octets':
            v = from_u16(dict_data[k])
        elif fmt == 'addr':
            v = from_addr(dict_data[k])
        #elif fmt == '1 octet data len':
            # This will be followed by 'variable len data'
            #v = b''
        elif fmt == 'variable len data':
            v_temp = from_data(dict_data[k])
            le = from_u8(len(v_temp))
            v = le + v_temp
        elif fmt == 'data':
            # it is ok to use 'data' for packing - and 'remaining' for unpacking
            v = from_data(dict_data[k])
        nb += v
    return nb

def make_acl(handle, length):
    template = (('hci command prefix',   '1 octet'),
                ('hci handle',           '2 octets'),
                ('hci length',           '2 octets'),
                ('l2cap length',         '2 octets'),
                ('channel',              '2 octets'))
    params =    {'hci command prefix':    0x02,
                 'hci handle':            handle,
                 'hci length':            length + 4,
                 'l2cap length':          length,
                 'channel':               ATT_CID}
    header = make_data(template, params)
    return header

def make_cmd(cmd, length):
    template  =  (('hci command prefix', '1 octet'),
                  ('hci command',        '2 octets'),
                  ('hci length',         '1 octet'))
    params =      {'hci command prefix':  0x01,
                   'hci command':         cmd,
                   'hci length':          length}
    header = make_data(template, params)
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

        template =   (('packet type',        '1 octet'),
                      ('event code',         '1 octet'),
                      ('parameter length',   '1 octet'),
                      ('subevent code',      '1 octet'),
                      ('status',             '1 octet'),
                      ('connection handle',  '2 octets'),
                      ('role',               '1 octet'),
                      ('peer_address_type',  '1 octet'),
                      ('peer address',       'addr'),
                      ('connection interval','2 octets'),
                      ('peripheral latency', '2 octets'),
                      ('supervision timeout','2 octets'),
                      ('clock accuracy',     '1 octet')
                     )

        (di, length) = make_dict(template, data)
        address = di["peer address"]
        status = di["status"]
        print("LE Connection Complete")
        print("Status: {:02x} Address: {}".format(status, address))

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

        adv_templ =  (('event type',         '1 octet'),
                      ('address type',       '1 octet'),
                      ('address',            'addr'),
                      ('data',               'variable len data'),
                      ('rssi',               '1 octet')
                     )
        template =   (('packet type',        '1 octet'),
                      ('event code',         '1 octet'),
                      ('parameter length',  '1 octet'),
                      ('subevent code',      '1 octet'),
                      ('reports',            'counted array', adv_templ)
                     )

        (di, length) = make_dict(template, data)
        print("LE Advertising Report")
        for adv in di["reports"]:
            address = adv["address"]
            data = adv["data"]
            print("Address: {}".format(address))
            i = 0
            while i < len(data):
                dat_len = data[i]
                if dat_len > 0:
                    typ = data[i+1]
                    dat = data[i + 2 : i + dat_len + 1]
                    print("Length: {:3} Type: {:02x}  Data: {}      {}".format(dat_len, typ, as_hex(dat), as_printable(dat)))
                    i += dat_len
                i += 1
                    
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

        template =   (('packet type',        '1 octet'),
                      ('event code',         '1 octet'),
                      ('parameter length',   '1 octet'),
                      ('subevent code',      '1 octet'),
                      ('status',             '1 octet'),
                      ('connection handle',  '2 octets'),
                      ('connection interval','2 octets'),
                      ('peripheral latency', '2 octets'),
                      ('supervision timeout','2 octets')
                     )

        (di, length) = make_dict(template, data)
        handle = di["connection handle"]
        status = di["status"]
        print("LE Connection Update Complete")
        print("Handle: {:04x} Status: {02x}".format(handle, status))
        
        self.handle = handle         # save this for other commands to use

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

        print("READ REMOTE FEATURES COMPLETE")

    def on_hci_meta_event(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.65 LE Meta event (p2235)
        # Event_code = 0x3e
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     subevent_code                                  1 octet
        #     data                                           n octets

        template =   (('packet type',        '1 octet'),
                      ('event code',         '1 octet'),
                      ('parameter length',   '1 octet'),
                      ('subevent code',      '1 octet'),
                     )
        (di, length) = make_dict(template, data)

        subevent_code = di['subevent code']
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
            print(di)

    def on_hci_event_disconnect_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.5 HCI_Disconnection_Complete (p2163)
        # HCI_Disconnection_Complete = 0x05
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     status                                         1 octet
        #     connection_handle                              2 octets
        #     reason                                         1 octet

        template =   (('packet type',           '1 octet'),
                      ('event code',            '1 octet'),
                      ('parameter length',      '1 octet'),
                      ('status',                '1 octet'),
                      ('connection handler',    '2 octets'),
                      ('reason',                '1 octet')
                     )

        (di, length) = make_dict(template, data)
        print("Event: HCI Disconnection Complete")
        print(di)

    def on_hci_event_command_complete(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.14 HCI Command Complete (p2177)
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     num_hci_command_packets                        1 octet
        #     command_opcode                                 2 octets
        #     return_parameters                              n octets

        template =   (('packet type',           '1 octet'),
                      ('event code',            '1 octet'),
                      ('parameter length',      '1 octet'),
                      ('num command packets',   '1 octet'),
                      ('command opcode',        '2 octets'),
                      ('status',                '1 octet')           # assume just one status message
                     )

        (di, length) = make_dict(template, data)
        print("Event: HCI Command Complete")

        cmd = di['command opcode']
        status = "Success" if di['status'] == HCI_SUCCESS else "Failure"
        self.command_complete = cmd
        self.command_status = status

        if   cmd == 0x200B:                   # LE Set Scan Paramaters
            print('LE Scan Parameters Set:',status);
        elif cmd == 0x200c:                   # LE Set Scan Enable
            print('LE Scan Enable Set:', status)
        elif cmd == 0x2006:                   # LE Set Advertising Parameters
            print('LE Advertising Parameters Set:', status)
        elif cmd == 0x2008:                   # LE Set Advertising Data
            print('LE Advertising Data Set:', status)
        elif cmd == 0x2009:                   # LE Set Scan Repsonse Data
            print('LE Scan Response Data Set:', status)
        elif cmd == 0x200a:                   # LE Set Advertise Enable
            print('LE Advertise Enable Set:', status)
        else:
            print('LE Unknown Command:', hex(cmd), status)
            print(di)

    def on_hci_event_command_status(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.15 HCI_Command_Status (p2179)
        # HCI_Command_Status = 0x0f
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     status                                         1 octet
        #     num_hci_command_packets                        1 octet
        #     command_opcode                                 2 octets

        template =   (('packet type',           '1 octet'),
                      ('event code',            '1 octet'),
                      ('parameter length',      '1 octet'),
                      ('status',                '1 octet'),
                      ('number of hci packets', '1 octet'),
                      ('command opcode',        '2 octets')
                     )

        (di, length) = make_dict(template, data)
        opcode = di["command opcode"]
        status = di["status"]

        print("Event: HCI Command Status")
        print("Opcode: {:02x} status: {:02x}".format(opcode, status))
        print(di)

    def on_hci_number_of_completed_packets(self, data):
        # Specification v5.4  Vol 4 Part E 7.7.19 HCI Number Of Completed Packets (p2184)
        #     [packet_type                                   1 octet]
        #     [event_code                                    1 octet]
        #     [parameter_length                              1 octet]
        #     num_handles                                    1 octet
        #     connection handle[i]                           2n octets
        #     num completed packets[i]                       2n octets

        print("Event: HCI Number Of Completed Packets")
        print("!! DOING NOTHING")

    def on_hci_event_packet(self, data):
        # Specification v5.4  Vol 4 Part E 5.4.4 HCI Event Packet (p1804)
        #     [packet_type                                   1 octet]
        #     event_code                                     1 octet
        #     parameter_length                               1 octet
        #     parameters                                     n octets

        template =   (('packet type',           '1 octet'),
                      ('event code',            '1 octet'),
                     )

        (di, length) = make_dict(template, data)
        evt = di['event code']
        print("HCI Event Packet:", hex(evt))

        if   evt == 0x0f:               # Command Status
            self.on_hci_event_command_status(data)
        elif evt == 0x05:               # Disconnection Complete
            self.on_hci_event_disconnect_complete(data)
        elif evt == 0x3e:               # LE Meta Event
            self.on_hci_meta_event(data)
        elif evt == 0x0e:               # Command complete
            self.on_hci_event_command_complete(data)
        elif evt == 0x13:               # Number of Completed Packets
            self.on_hci_number_of_completed_packets(data)
        else:
            print("HCI Event: Unhandled", hex(evt))

    def on_acl_data_packet(self, data):
        # Specification v5.4  Vol 4 Part E 5.4.2 HCI ACL Packet (p1801)
        #     [packet_type                                  1 octet]
        #     handle (BC[2] PB[2] handle[12])               2 octets
        #     packet length                                 2 octets
        #     data_length                                   2 octets
        #     channel                                       2 octets
        #     data                                          n octets

        template =   (('packet type',           '1 octet'),
                      ('handle field',          'bitfield 16',
                       (('bc',     14, 2),
                        ('pb',     12, 2),
                        ('handle', 0, 12))),
                      ('packet length',         '2 octets'),
                      ('rest',                  'remaining'))

        hdr_templ =  (('data size',             '2 octets'),
                      ('channel',               '2 octets'),
                      ('data',                  'remaining'),
                     )

        (di, length) = make_dict(template, data)

        print("ACL Packet")
        handle = di["handle"]
        bc = di["bc"]
        pb = di["pb"]
        length = di["packet length"]
        
        print('ACL header: handle: {}  bc: {}  pb: {}'.format(handle, bc, pb))
        # flags == ACL_START and channel == ATT_CID ??

        if pb & 0x01 == 0:
            (hdr_di, hdr_len) = make_dict(hdr_templ, di["rest"])

            channel = hdr_di["channel"]
            data = hdr_di["data"]
            size = hdr_di["data size"]
            full_packet = length - size == 4

            print("Channel: {} Length: {} Data size: {} Full packet? {}".format(channel, length, size, full_packet))
            print("ACL data:  ", as_hex(data))

            if not full_packet:  # This is not a full packet, so start to store the acl_packet
                self.acl_total_length = size
                self.acl_packet = data

        if pb & 0x01 == 1:
            print("ACL Packet Continuation")
            data = di["rest"]
            self.acl_packet += data
            print("ACL data:  ", as_hex(data))
            if len(self.acl_packet) == self.acl_total_length:
                print("ACL Packet Final")
                print("Full ACL data: ", as_hex(self.acl_packet))
            

    # HCI packet received handler

    def on_data(self, data):
        # Specification v5.4  Vol 4 Part E 5.4.4 HCI Event Packet (p1804)
        # Specification v5.4  Vol 4 Part E 5.4.2 HCI ACL Packet (p1801)
        #     packet_type                                    1 octet

        packet_type = data[0]
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


    def do_set_advertising_parameter(self):
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
        template  =  (('min interval',       '2 octets'),
                      ('max interval',       '2 octets'),
                      ('adv type',           '1 octet'),
                      ('own addr type',      '1 octet'),
                      ('peer addr type',     '1 octet'),
                      ('peer address',       'addr'),
                      ('adv channel map',    '1 octet'),
                      ('adv filter policy',  '1 octet'))
        params =      {'min interval':        0x00a0,
                       'max interval':        0x00a0,
                       'adv type':            0x00,
                       'own addr type':       0x00,
                       'peer addr type':      0x00,
                       'peer address':        '11:22:33:44:55:66',
                       'adv channel map':     0x07,
                       'adv filter policy':   0x00}
        packet = make_data(template, params)
        #cmd = make_cmd(0x2006, len(packet)) + packet
        #self.send(cmd)
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
        pad = bytes(b'\x00' * (31 - len(data)))
        template =   (('data',               'variable len data'),
                      ('pad',                'data'))
        params =      {'data':                data,
                       'pad':                 pad}
        packet = make_data(template, params)
        #cmd = make_cmd(0x2008, len(packet)) + packet
        #self.send(cmd)
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
        template =   (('data',               'variable len data'),
                      ('pad',                'data'))
        params =      {'data':                data,
                       'pad':                 pad}
        packet = make_data(template, params)
        #cmd = make_cmd(0x2009, len(packet)) + packet
        #self.send(cmd)
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
        template =   (('enable',             '1 octet'),)
        params =      {'enable':              0x01 if enabled else 0x00}
        packet = make_data(template, params)
        #cmd = make_cmd(0x200a, len(packet)) + packet
        #self.send(cmd)
        self.send_command(0x200a, packet)

    def do_set_scan_parameters(self):
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
        template =   (('type',               '1 octet'),
                      ('internal',           '2 octets'),
                      ('window',             '2 octets'),
                      ('own addr',           '1 octet'),
                      ('filter',             '1 octet'))

        params =      {'type':                SCAN_TYPE_ACTIVE,
                       'internal':            0x0060,
                       'window':              0x0060,
                       'own addr':            LE_PUBLIC_ADDRESS,
                       'filter':              FILTER_POLICY_NO_WHITELIST}
        packet = make_data(template, params)
        #cmd = make_cmd(0x200b, len(packet)) + packet
        #self.send(cmd)
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

        enable = 0x01 if enabled else 0x00
        dups   = 0x01 if duplicates else 0x00
        print(cmd_text, "LE Set Scan Enable" if enable else "LE Set Scan Disable")
        template =   (('enable',             '1 octet'),
                      ('duplicates',         '1 octet'))
        params =      {'enable':              enable,
                       'duplicates':          dups }
        packet = make_data(template, params)
        #cmd = make_cmd(0x200c, len(packet)) + packet
        #self.send(cmd)
        self.send_command(0x200c, packet)

    def do_create_connection(self, addr, addr_type):
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
        template  =  (('interval',           '2 octets'),
                      ('window',             '2 octets'),
                      ('initiator filter',   '1 octet'),
                      ('peer address type',  '1 octet'),
                      ('address',            'addr'),
                      ('own address type',   '1 octet'),
                      ('min interval',       '2 octets'),
                      ('max interval',       '2 octets'),
                      ('latency',            '2 octets'),
                      ('supervision timeout','2 octets'),
                      ('min ce length',      '2 octets'),
                      ('max ce length',      '2 octets'))

        params =      {'interval':            0x0060,
                       'window':              0x0060,
                       'initiator filter':    0x00,
                       'peer address type':   addr_type,
                       'address':             addr,
                       'own address type':    0x0000,
                       'min interval':        0x0018,
                       'max interval':        0x0028,
                       'latency':             0x0000,
                       'supervision timeout': 0x002a,
                       'min ce length':       0x0000,
                       'max ce length':       0x0000}

        packet = make_data(template, params)
        #cmd = make_cmd(0x200d, len(packet)) + packet
        #self.send(cmd)
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
        template =   (('address type',       '1 octet'),
                      ('address',            'addr'))

        params =      {'address type':        addr_type,
                       'address':             addr }
        packet = make_data(template, params)
        #cmd = make_cmd(0x2011, len(packet)) + packet
        #self.send(cmd)
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
        template =   (('handle',            '2 octets'), # must have , to make it a tuple
                     )
        params =      {'handle':             self.handle}
        packet = make_data(template, params)
        #cmd = make_cmd(0x2016, len(packet)) + packet
        #self.send(cmd)
        self.send_command(0x2016, packet)

    # ACL commands

    def do_att_exchange_mtu_req(self):
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
        template =   (('att command',       '1 octet'),
                      ('mtu size',          '2 octets'))
        params =      {'att command':        0x02,
                       'mtu size':           517}
        packet = make_data(template, params)
        cmd = make_acl(self.handle, len(packet)) + packet
        self.send(cmd)


    def do_att_find_information_req(self, start, end):
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
        template =   (('att command',       '1 octet'),
                      ('starting handle',   '2 octets'),
                      ('ending handle',     '2 octets'))
        params =      {'att command':        0x04,
                       'starting handle':    start,
                       'ending handle':      end }
        packet = make_data(template, params)
        cmd = make_acl(self.handle, len(packet)) + packet
        self.send(cmd)


    def do_att_read_by_type_req(self, low_uuid, high_uuid, uuid):
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
        template =   (('att command',       '1 octet'),
                      ('low uuid',          '2 octets'),
                      ('high uuid',         '2 octets'),
                      ('uuid',              '2 octets'))
        params =      {'att command':        0x08,
                       'low uuid':           low_uuid,
                       'high uuid':          high_uuid,
                       'uuid':               uuid }
        packet = make_data(template, params)
        cmd = make_acl(self.handle, len(packet)) + packet
        self.send(cmd)


