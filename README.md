# HCI-BLE-Python
Python library to access BLE functions using HCI layer   

Very simple, using the BLE commands directly without any interpretation or pythonic class creation    

Credits: based on work in Scapy, Bumble and python-hcipy

```
Scapy:        https://github.com/secdev/scapy/
Scapy code:   https://github.com/secdev/scapy/blob/master/scapy/layers/bluetooth.py
Bumble:       https://github.com/google/bumble
Python-hcipy: https://github.com/TheBubbleworks/python-hcipy
```

Simple use of the HCI layer to run BLE commands using python.   
Tested on Ubuntu using Bluez and a KinivQ USB dongle. Some other dongles didn't work.   

Key learning - you need to stop Bluez interfering, and you need to bring the hci device down to do that - and open as a User socket.   Scapy has special code for that.


+-----------------+------------------------------------------------------------------------+    
| Packet type     |                                                                        |		  			
| 8		  |                                                                        |
+------------------------------------------------------------------------------------------+

Command
0x01 							|	
	OpCode	Length	DATA				
	OGF	OCF						
	6	10	8					
Async data
0x02								
	BC	PB	Handle	Length				
	2	2	12	16				
					Length	Channel		
					16	16
[0x04]		
							ATT Cmd	DATA
							8	
Event
0x04								
	Event Code	Length	DATA					
	8	8						


