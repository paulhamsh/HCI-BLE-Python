from ble import *

MY_SCAN_DATA = bytes.fromhex('09094d79424c45446576'  # 0x09  Complete Local Name
                            )
MY_ADV_DATA =  bytes.fromhex('020106' +              # 0x01 Flags
                             '0303eeff'              # 0x03 16 bit Servuce UUID Complete
                            )

class BLE(BluetoothLEConnection):
    def test(self):
        addr = 'D8:3A:DD:41:84:47'
        addr_type = LE_PUBLIC_ADDRESS
 
        self.do_set_scan(False, False)
        self.do_add_device_to_accept_list(addr, addr_type)
        self.do_set_scan_parameters()
        self.do_set_scan(True, True)
        self.do_set_scan(False, False)
        self.do_create_connection(addr, addr_type)  
        self.do_read_remote_used_features()
        self.do_read_by_type_request(0x0000, 0xffff, 0x2800)
        self.do_set_mtu()
        scan_rsp_data = MY_SCAN_DATA
        adv_data = MY_ADV_DATA
        self.do_set_advertise_enable(False)
        self.do_set_advertising_parameter()
        self.do_set_advertising_data(adv_data)
        self.do_set_scan_response_data(scan_rsp_data)

           
    def conn(self):
        addr = 'D8:3A:DD:41:84:47'
        addr_type = LE_PUBLIC_ADDRESS
 
        self.do_set_scan(False, False)
        self.do_add_device_to_accept_list(addr, addr_type)
        self.do_set_scan_parameters()
        self.do_set_scan(True, True)
        self.wait_listen(10)

        self.do_set_scan(False, False)
        self.do_create_connection(addr, addr_type)  
        self.wait_listen(5)

        self.do_read_remote_used_features()
        self.wait_listen(5)

        self.do_set_mtu()
        self.wait_listen(5)
        self.do_read_by_type_request(0x0001, 0xffff, 0x2800)
        self.wait_listen(30)

        
    def adv(self):
        scan_rsp_data = MY_SCAN_DATA
        adv_data = MY_ADV_DATA

        self.do_set_advertise_enable(False)
        self.wait_listen(1)
        self.do_set_advertising_parameter()
        self.wait_listen(1)
        self.do_set_advertising_data(adv_data)
        self.wait_listen(1)
        self.do_set_scan_response_data(scan_rsp_data)
        self.wait_listen(1)
        self.do_set_advertise_enable(True)
        self.wait_listen(50)
    
if __name__ == "__main__":
    ble = BLE(1)
    ble.conn()
    #ble.adv()

    
    print("DONE")
    
    
