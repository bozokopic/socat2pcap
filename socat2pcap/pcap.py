import io
import socket
import struct

from socat2pcap import common


class PcapStream:

    def __init__(self,
                 stream: io.RawIOBase,
                 ip_addr_a: str,
                 ip_addr_b: str,
                 tcp_port_a: int,
                 tcp_port_b: int):
        self._stream = stream

        self._addrs = {common.Direction.A_TO_B: socket.inet_aton(ip_addr_a),
                       common.Direction.B_TO_A: socket.inet_aton(ip_addr_b)}
        self._ports = {common.Direction.A_TO_B: tcp_port_a,
                       common.Direction.B_TO_A: tcp_port_b}
        self._seqs = {common.Direction.A_TO_B: 0,
                      common.Direction.B_TO_A: 0}

        self._stream.write(struct.pack("IHHIIII",
                                       0xa1b2c3d4,  # magic number
                                       2,  # major version
                                       4,  # minor version
                                       0,  # reserved
                                       0,  # reserved
                                       0xffffffff,  # snap len
                                       101))  # link type - LINKTYPE_RAW
        self._stream.flush()

    def write(self, msg: common.Msg):
        direction = msg.direction
        inverted_direction = common.invert_direction(direction)

        seq = self._seqs[direction]
        ack = self._seqs[inverted_direction]

        tcp_len = 20 + len(msg.data)
        tcp_header = struct.pack(
            ">HHIIBBHHH",
            self._ports[direction],  # src port
            self._ports[inverted_direction],  # dst port
            seq,  # seq number
            ack,  # ack number
            0x50,  # data offset
            0,  # flags
            0xffff,  # window size
            0,  # checksum
            0)  # urgent pointer

        ip_len = 20 + tcp_len
        ip_header = struct.pack(
            ">BBHHHBBH4s4s",
            0x45,  # ipv4 + 5*32 bit header
            0,  # dscp + ecn
            ip_len,  # total length
            0,  # identification
            0,  # flag + fragment offset
            0xff,  # ttl
            6,  # protocol - tcp
            0,  # checksum
            self._addrs[direction],  # src addr
            self._addrs[inverted_direction])  # dst addr

        packet_header = struct.pack(
            "IIII",
            int(msg.timestamp),
            int((msg.timestamp - int(msg.timestamp)) * 1E6),
            ip_len,
            ip_len)

        self._stream.write(packet_header)
        self._stream.write(ip_header)
        self._stream.write(tcp_header)
        self._stream.write(msg.data)
        self._stream.flush()

        self._seqs[direction] += len(msg.data)
