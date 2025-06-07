#!/bin/bash


# create python environment (avoids changing your system and keeps installation local)
python3 -m venv .venv

# install needed package into this virtual environment
.venv/bin/pip install pyserial

# use python from this virtual environment
./.venv/bin/python ./serial-pcap.py -b 19200 --fifo /tmp/wireshark /dev/ttyUSB0

