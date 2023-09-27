# HCI-BLE-Python

**What is this?**    

A Python library to access BLE functions using the HCI layer provided by Bluez on Linux.      
I provides access to the BLE commands from the Bluetooth specification, with no class layers or interpretation.  
I could form the basis of a BLE library or just a BLE application.   
Only a bit is implemented, enough to prove it works.  
It can scan, connect, send and receive LE commands, and advertise.   

**Credits**

This is derived from work in Scapy, Bumble and python-hcipy, all of which have been incredibly useful in creating this.

```
Scapy:                          https://github.com/secdev/scapy/
Scapy code:                     https://github.com/secdev/scapy/blob/master/scapy/layers/bluetooth.py
Bumble:                         https://github.com/google/bumble
Python-hcipy:                   https://github.com/TheBubbleworks/python-hcipy

Bluetooth Specification v5.4:   https://www.bluetooth.com/specifications/specs/core-specification-5-4/

And a really useful article which pointed me in the right direction: 
  https://stackoverflow.com/questions/43703507/direct-control-of-hci-device-bypass-bluetooth-drivers-on-linux
```
**Background**

Simple use of the HCI layer to run BLE commands using python.   
Tested on Ubuntu using Bluez and a KinivQ USB dongle. Some other dongles didn't work.   

Key learning - you need to stop Bluez interfering, and you need to bring the hci device down to do that - and open as a User socket.   Scapy has special code for that.


**Compatibility**
Tested on Ubuntu using Bluez and a KinivQ USB dongle. Some other dongles didn't work.  
On Raspberry Pi ZeroW:   TP Link: Bus 001 Device 002: ID 2357:0604 TP-Link TP-Link UB5A Adapter
On Ubuntu Desktop PC:    Kinivq:   

**The BLE HCI interface**   

The BLE HCI interface is packet based and has three relevant packet types - command, asynchronous data and event.   
The formats are shown in the diagrams below.   
Each packet starts with the event type as the first byte ('octet' in BLE specification documentation).   


<p align="center">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Packet Types.jpg" >
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Command Packet.jpg">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Command Opcode.jpg">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI ACL Packet.jpg">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Event Packet.jpg">
</p>

