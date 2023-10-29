## NINA Pinouts


RP2040 Serial 2 is connected to NINA UART.   
Pin D24 / GPIO 3 is taken low for 100ms to reset the NINA.    
If D26 / GPIO 9 is held low on boot it enters BLE mode.    

```
RP2040

NINA_RESETN     D24          3

SERIAL2_TX      D25          8
SERIAL2_RX      D26          9
SERIAL2_CTS     D27          10
SERIAL2_RTS     D28          11


SPI1_MISO       D25          8
SPI1_MOSI       D28          11
SPI1_SCK        D29          14
SPI1_SS         D10          5

SPIWIFI_SS      D26          9
SPIWIFI_ACK     D27          10
SPIWIFI_RESET   NINA_RESETN
SPIWIFI         SPI1       


NINA            RP2040
RSTN NINA       RESET_N       3

UART TX         1             8
UART RX         3             9
UART CTS        12            10
UART RTS        33            11

SPI_CS          5
SPI_ACK         33
SPI_COPI        12
SPI_CIPI        23
SPI_SCK         18

Check SPI_CS (5) is LOW = BLE

RP2040 – make 24 and 25 HIGH

Baud 115200
```
```
https://github.com/earlephilhower/arduino-pico/blob/master/variants/arduino_nano_connect/pins_arduino.h
https://github.com/arduino/nina-fw/blob/master/main/sketch.ino.cpp
https://docs.arduino.cc/hardware/nano-rp2040-connect
```
