# References   
Micropython instructions: https://github.com/micropython/micropython/blob/master/ports/esp32/README.md
usbipd-win instructions: https://devblogs.microsoft.com/commandline/connecting-usb-devices-to-wsl/


# Instructions   
Install MSI for USBIPD (provide access to ESP32 over USB into WSL) from  https://github.com/dorssel/usbipd-win/releases
 
***Windows***
```
cd "c:\Program Files\usbpid-win"
usbipd wsl list
usbipd wsl attach --busid <busid>

# Install Ubuntu in WSL

wsl --install Ubuntu
[provide username and password]
```

***WSL***
```
# Then you are in WSL

sudo bash
apt update
apt upgrade


# USB access for Windows
apt install linux-tools-virtual hwdata
update-alternatives --install /usr/local/bin/usbip usbip `ls /usr/lib/linux-tools/*/usbip | tail -n1` 20

# ESP IDF installation
apt install python3.8-venv
git clone -b v5.0.2 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf

./install.sh esp32
source export.sh

# Micropython installation
cd ~
git clone https://github.com/micropython/micropython
cd micropython

apt install cmake

make -C mpy-cross

cd ports/esp32
make submodules
make

# Install to ESP32
make erase
make deploy
```

***Windows***
```
# Close USB access in Windows so can see ESP32
Windows:
usbipd wsl detach --busid <busid>
```
