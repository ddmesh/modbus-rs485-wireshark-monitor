License
-------
This script and related content is licensed under the MIT license.
~~~
Copyright 2014 Matthijs Kooijman <matthijs@stdin.nl>
Copyright 2024 Stephan Enderlein (modified and fixed)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
~~~

# Introduction
This Python script allows you to monitor Modbus RTU messages with Wireshark. \
It connects to a serial port where the Modbus USB adapter (RS485) is attached and creates a file pipe (FIFO). \
All captured data is packaged into pcap packets that can be received via this pipe by Wireshark to display the Modbus packets.

# Changes / Added Features
Project is originally cloned from https://github.com/Pinoccio/tool-serial-pcap

- Use a user DLT (data link type) and remove non-working pcap encapsulation
- Remove blocking code that prevents receiving data from the USB Modbus adapter
- Keep the serial port always open instead of opening/closing on each cycle (avoids losing data)
- Add Modbus RTU packet parser
- Output packets on the command line (while forwarding to Wireshark via the pipe /tmp/wireshark)

# Installation and Start
There are two ways: directly in your system or indirectly in a venv via serial-pcap.sh

**Manually**
~~~sh
# Install python3 on your system
apt install python3

# Install dependency on your system
pip install pyserial

# Start script
/serial-pcap.py -b 19200 --fifo /tmp/wireshark /dev/ttyUSB0
~~~

**Indirectly via venv**
The virtual environment directory is created in ./.venv.
~~~sh
# Start script (via venv)
./serial-pcap.sh
~~~

## Prepare Wireshark
Wireshark allows reading data from pipes and handles the data the same way as it loads a pcap file.
The script first creates a pcap header, and all subsequent request and response packets are packed into their own pcap records.

To ensure Wireshark receives the required pcap header, Wireshark must be configured and started **BEFORE** starting the ```serial-pcap.py``` script.

- Start serial-pcap.py
- Start Wireshark
- Configure Wireshark to process the user DLT (used by script in the pcap header) as Modbus RTU packets:
  - Go to ```Edit->Preferences->Protocol->DLT_USER```
  - Edit *Encapsulations Table*
  - Add a new entry (if not already), select ```DLT=147``` for DLT, and set _Payload protocol_ to ```mbrtu```
  - Press OK and close Preferences
- Go to ```Capture->Options->Manage Interfaces->Pipes```, add the pipe ```/tmp/wireshark``` and press OK
- **Select the pipe** (in current dialog, which is now added to the list)
- Apply the display filter "modbus"
- press "Start"

If the pipe was already created before (manually via mkfifo /tmp/wireshark or by a previous call to serial-pcap),
Wireshark will start monitoring.

Unfortunately, Wireshark only remembers the Encapsulations Table entries, but not the pipe.
The pipe must be configured each time after starting Wireshark.

## Windows WSL2 / Linux
When running on Windows WSL2, use **"WSL USB Manager"** to pass the USB RS485 dongle to WSL.
- Add the WSL2 user to the 'dialout' group to allow access to /dev/ttyX....
  `usermod -aG dialout your-user-name`
- Install Wireshark within WSL2 to access the /tmp/wireshark (pipe).
  `apt install wireshark`
- Add the user to 'wireshark' group
    `usermod -aG wireshark your-user-name`

Command line tool: https://github.com/dorssel/usbipd-win
Gui for command line tool: https://gitlab.com/alelec/wsl-usb-gui



# Links
- https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html
- https://www.tcpdump.org/linktypes.html

