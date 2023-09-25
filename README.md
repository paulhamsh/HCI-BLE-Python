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
  


<p align="center">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictues/HCI Packet Types.jpg" width="700" title="connections">
</p>
