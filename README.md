# HCI-BLE-Python

## What is this? 

A Python library to access BLE functions using the HCI layer.   
Currently works with the HCI laver provided by Bluez on Linux and UART HCI on the Nano Connect RP2040.   

It provides access to the BLE commands from the Bluetooth specification, with minimal class layers or interpretation.  
It could form the basis of a BLE library or just a BLE application.   
Only a bit is implemented, enough to prove it works.  
It can scan, connect, send and receive LE commands, and advertise.   

BLE is a simple part of the Bluetooth specification, and doesn't require much code.   


## Credits

This is derived from work in Scapy, Bumble and python-hcipy, all of which have been incredibly useful in creating this.   
I only discovered Arduino BLE later in the project, and it is a good simple implementation of BLE - like this project, but in C++.   

```
Scapy:                          https://github.com/secdev/scapy/
Scapy code:                     https://github.com/secdev/scapy/blob/master/scapy/layers/bluetooth.py
Bumble:                         https://github.com/google/bumble
Python-hcipy:                   https://github.com/TheBubbleworks/python-hcipy
ArduinoBLE:                     https://github.com/arduino-libraries/ArduinoBLE   

Bluetooth Specification v5.4:   https://www.bluetooth.com/specifications/specs/core-specification-5-4/

And a really useful article which pointed me in the right direction: 
  https://stackoverflow.com/questions/43703507/direct-control-of-hci-device-bypass-bluetooth-drivers-on-linux
```

## Background

Simple use of the HCI layer to run BLE commands using python.      
Key learning - you need to stop Bluez interfering, and you need to bring the hci device down to do that - and open as a User socket.   Scapy has special code for that.


## Compatibility  
Tested on Ubuntu using Bluez and a KinivQ USB dongle. Some other dongles didn't work.    

On Ubuntu Desktop PC and Pi Zero W:    
```Kinivo BTD-400:   Bus 001 Device 002: ID 0a5c:21e8 Broadcom Corp. BCM20702A0 Bluetooth 4.0 ```  

On Raspberry Pi Zero W:   
```TP Link:          Bus 001 Device 002: ID 2357:0604 TP-Link TP-Link UB5A Adapter ```  

Doesn't work anywhere - every command responds with a failure status:    
```Trust:            Bus 001 Device 003: ID 0a5c:2101 Broadcom Corp. BCM2045 Bluetooth```

Also tested on microcontrollers:

```Nano Connect RP2040:  UART HCI to NINA W102 on-board BT chip```   
  
## The BLE HCI interface

The BLE HCI interface is packet based and has three relevant packet types - command, asynchronous data and event.   
The formats are shown in the diagrams below.   
Each packet starts with the event type as the first byte ('octet' in BLE specification documentation).   


## Commands and events
```
HCI Commands and events                          Specification v5.4  Vol 4 Part E 7                 (p1835)
    HCI Events                                   Specification v5.4  Vol 4 Part E 7.7               (p2156)
    LE Meta Events                               Specification v5.4  Vol 4 Part E 7.7.65            (p2235)
    LE Commands                                  Specification v5.4  Vol 4 Part E 7.8               (p2341)

    ACL data packets                             Specification v5.4  Vol 4 Part E 5.4.2             (p1801)
```
All commands for LE are in the 7.8 section.
Some events are HCI events (command complete, command status) but most are LE Meta events.

Check for command completion
To check for a command completion, need to check the HCI Command Complete and/or the HCI Meta Event for that specific command.

```
HCI Command Complete
Event code          0x0e                      Command opcode           0xabcd

HCI Meta Event                 
Event code          0x3e                      Subevent code            0xab
```
So – any wait for a command response should be waiting for HCI Command Complete or HCI Meta Event and a specific subevent code. It needs to be specific.

## H4 Packet Formats

<p align="center">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Packet Types.jpg" >
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Command Packet.jpg">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Command Opcode.jpg">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI ACL Packet.jpg">
  <img src="https://github.com/paulhamsh/HCI-BLE-Python/blob/main/pictures/HCI Event Packet.jpg">
</p>

