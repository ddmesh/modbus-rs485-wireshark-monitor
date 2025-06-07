#!/usr/bin/env python3


# Copyright 2014 Matthijs Kooijman <matthijs@stdin.nl>
# Copyright 2024 Stephan Enderlein (modified and fixed)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# This script is intended to read raw packets (currently only 802.15.4
# packets prefixed by a length byte) from a serial port and output them
# in pcap format.

import os
import sys
import time
import errno
import serial
import struct
import select
import binascii
import datetime
import argparse
import binascii

version = "1.1"
# This script reads packets from a serial port and writes them to a pcap file or fifo.
# It can be used to capture packets from devices that communicate over serial, such as
# 802.15.4 devices, modbus devices, etc.
# The script can also print the packets in a human-readable format to stdout.

class Formatter:
    def __init__(self, out):
        self.out = out

    def fileno(self):
        return self.out.fileno()

    def close(self):
        self.out.close()

class PcapFormatter(Formatter):
    def write_header(self):
        self.out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            1024,         # max length of captured packets, in octets
            # https://www.tcpdump.org/linktypes.html
            # https://www.geeksforgeeks.org/user-dlts-protocol-table-in-wireshark/
            147,   # data link type (DLT) user specific
        ))
        self.out.flush()

    def write_packet(self, data):
        now = datetime.datetime.now()
        timestamp = int(time.mktime(now.timetuple()))

        # pcap packet record
        self.out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            now.microsecond,  # timestamp microseconds
            len(data),     # number of bytes of packet
            len(data),     # actual length of packet
        ))

        # write payload
        #sl=slice(len(data))
        # print("write: {}".format(binascii.hexlify(data).decode()))
        self.out.write(data)
        self.out.flush()

# prints data in human readable format on console
class HumanFormatter(Formatter):
    # print no header
    def write_header(self):
        pass

    def write_packet(self, data):
        self.out.write(binascii.hexlify(data).decode())
        self.out.write("\n")
        self.out.flush()

def open_fifo(options, name):
    try:
        os.mkfifo(name);
    except FileExistsError:
        pass
    except:
        raise

    if not options.quiet:
        print("Waiting for fifo to be openend...")
    # This blocks until the other side of the fifo is opened
    ret = open(name, 'wb')
    print("Fifo connected")
    return ret

def setup_output(options):
    if options.fifo:
        print("Write to fifo: {}".format(options.fifo))
        return PcapFormatter(open_fifo(options, options.fifo))
    elif options.write_file:
        print("Write to file: {}".format(options.write_file))
        return PcapFormatter(open(options.write_file, 'wb'))
    else:
        print("Write to stdout")
        return HumanFormatter(sys.stdout)

def main():
    parser = argparse.ArgumentParser(description='converts packets read from a serial port into pcap format')
    parser.add_argument('port',
                        help='The serial port to read from')
    parser.add_argument('-b', '--baudrate', default=19200, type=int,
                        help='The baudrate to use for the serial port (defaults to %(default)s)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Do not output any informational messages')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('-F', '--fifo',
                        help='Write output to a fifo instead of stdout. The fifo is created if needed and capturing does not start until the other side of the fifo is opened.')
    output.add_argument('-w', '--write-file',
                        help='Write output to a file instead of stdout')

    options = parser.parse_args();

    try:
        if not options.quiet:
            print("serial-pcap.py version {}".format(version))
            print("Reading from serial port {} at {} baud".format(options.port, options.baudrate))
            print("Output will be written to {}".format(options.fifo if options.fifo else options.write_file if options.write_file else "stdout"))
        timeout=0.01
        try:
          ser = serial.Serial(options.port, options.baudrate,serial.EIGHTBITS,serial.PARITY_EVEN,serial.STOPBITS_ONE,timeout)
        except serial.SerialException as e:
            print(f"Error opening serial port {options.port}: {e}")
            sys.exit(1)

        print("Opened {} at {}".format(options.port, options.baudrate))
        out = setup_output(options)

        print("Write pcap header to pipe")
        out.write_header()

        while True:
            do_sniff_once(options,out,ser)

        ser.close()
        out.close()
    except KeyboardInterrupt:
        pass


def modbus_packet_info(pkt):
    if len(pkt) < 4:
        return "unvollständig"
    unit_id = pkt[0]
    func = pkt[1]
    # Default-Werte
    reg = count = val = byte_count = None
    crc = ""
    payload = ""
    typ = ""
    # Exception Response
    if func & 0x80 and len(pkt) == 5:
        typ = "Exception"
        crc = pkt[-2:].hex()
    # Read Request (1,2,3,4)
    elif func in (1,2,3,4) and len(pkt) == 8:
        typ = "Request"
        reg = pkt[2]<<8 | pkt[3]
        count = pkt[4]<<8 | pkt[5]
        crc = pkt[6:8].hex()
    # Read Response (1,2,3,4)
    elif func in (1,2,3,4) and len(pkt) >= 5:
        typ = "Response"
        byte_count = pkt[2]
        payload = pkt[3:3+byte_count].hex()
        crc = pkt[3+byte_count:3+byte_count+2].hex()
    # Write Single Coil/Register (5,6)
    elif func in (5,6) and len(pkt) == 8:
        typ = "Write"
        reg = pkt[2]<<8 | pkt[3]
        val = pkt[4]<<8 | pkt[5]
        crc = pkt[6:8].hex()
    # Write Multiple (15,16)
    elif func in (15,16):
        if len(pkt) >= 8 and len(pkt) != 8:
            typ = "WriteMultiReq"
            reg = pkt[2]<<8 | pkt[3]
            count = pkt[4]<<8 | pkt[5]
            byte_count = pkt[6]
            payload = pkt[7:7+byte_count].hex()
            crc = pkt[7+byte_count:7+byte_count+2].hex()
        elif len(pkt) == 8:
            typ = "WriteMultiResp"
            reg = pkt[2]<<8 | pkt[3]
            count = pkt[4]<<8 | pkt[5]
            crc = pkt[6:8].hex()
    else:
        typ = "Unknown"
        crc = pkt[-2:].hex()
        payload = pkt[2:-2].hex() if len(pkt) > 4 else ""

    # Spaltenweise Ausgabe, feste Breite
    return (
        f"UnitID: {unit_id:3d}  "
        f"Func: {func:02X}  "
        f"{typ:<12} "
        f"Count: {count if count is not None else byte_count if byte_count is not None else '':<6} "
        f"Reg: {reg if reg is not None else '':<6} "
        f"CRC: {crc:<4}  "
        f"Payload: {payload}"
    )

def do_sniff_once(options, out, ser):
    if not hasattr(do_sniff_once, "buffer"):
        do_sniff_once.buffer = bytearray()
    buffer = do_sniff_once.buffer

    data = ser.read(1024)
    if data:
        buffer += data

    def read_exact_from_buffer(n):
        if len(buffer) < n:
            return None
        result = buffer[:n]
        del buffer[:n]
        return result

    while True:
        if len(buffer) < 4:
            break

        func_code = buffer[1]

        # 1. Exception Response (immer 5 Bytes)
        if func_code & 0x80 and len(buffer) >= 5:
            pkt_len = 5

        # 2. Write Single/Multiple Response (immer 8 Bytes)
        elif func_code in (5, 6, 15, 16) and len(buffer) >= 8:
            pkt_len = 8

        # 3. Read Response (Funktionscode 1-4, variable Länge, plausibler Byte Count)
        elif func_code in (1, 2, 3, 4):
            if len(buffer) < 5:
                print("Not enough data for Read Response")
                break
            byte_count = buffer[2]
            # Plausibilitätscheck: Byte Count nicht zu groß und nicht 0
            if 0 < byte_count < 250 and len(buffer) >= (1 + 1 + 1 + byte_count + 2):
                pkt_len = 1 + 1 + 1 + byte_count + 2
            # 4. Read Request (immer 8 Bytes, Funktionscode 1-4, wenn kein plausibler Byte Count)
            elif len(buffer) >= 8:
                pkt_len = 8
            else:
                break

        else:
            print(f"Unknown function code {func_code:02X}, skipping")
            # drop byte to avoid and continue with next byte
            buffer.pop(0)
            continue

        if len(buffer) < pkt_len:
            print(f"Not enough data for packet of length {pkt_len}, waiting for more data")
            break

        pkt = read_exact_from_buffer(pkt_len)
        if pkt:
            if not options.quiet:
              info = modbus_packet_info(pkt)
              print(f"{info}")
            try:
                out.write_packet(bytes(pkt))
            except OSError as e:
                if e.errno == errno.ESTRPIPE:
                    return
        else:
            break

if __name__ == '__main__':
    main()
