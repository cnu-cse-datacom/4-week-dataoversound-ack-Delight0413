import socket
import struct


recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

	
'''ethernet header'''
def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

'''ip header'''
def parsing_ip_header(data):
    ip_header = struct.unpack("!2bhHh1B1bH8B", data)
    ip_version = (ip_header[0] & 0xf0) >> 4
    ip_Length = ip_header[0] & 0xf
    ip_DS = (ip_header[1] & 0xfc) >> 2
    ip_ECN = ip_header[1] & 0x3
    ip_totalLength = ip_header[2]
    ip_ident = ip_header[3]
    ip_flags = hex(ip_header[4])
    ip_X = ip_header[4] & 0x8000 >> 15
    ip_D = ip_header[4] & 0x4000 >> 14
    ip_M = ip_header[4] & 0x2000 >> 13
    ip_offset = ip_header[4] & 0x1fff
    ip_TTL = ip_header[5]
    ip_protocol = ip_header[6]
    ip_checksum = hex(ip_header[7])
    ip_src = convert_ip_address(ip_header[8:12])
    ip_dst = convert_ip_address(ip_header[12:16])

    print("======ip_header======")
    print("ip_version:", ip_version)
    print("ip_Length:", ip_Length)
    print("differentiated_service_codepoint:", ip_DS)
    print("explicit_congestion_notification:", ip_ECN)
    print("total_length:", ip_totalLength)
    print("identification:", ip_ident)
    print("flags:", ip_flags)
    print(">>>reserved_bit:", ip_X)
    print(">>>not_fragments", ip_D)
    print(">>>fragments:", ip_M)
    print(">>>fragments_offset:", ip_offset)
    print("Time to live:", ip_TTL)
    print("protocol:", ip_protocol)
    print("header checksum:", ip_checksum)
    print("source_ip_address:", ip_src)
    print("dest_ip_address:", ip_dst)

    return ip_protocol

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(i)
    ip_addr = ".".join(map(str,ip_addr))
    return ip_addr

'''tcp header'''
def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2H2Ih3H", data)
    tcp_src = tcp_header[0]
    tcp_dst = tcp_header[1]
    tcp_sNum = tcp_header[2]
    tcp_ack = tcp_header[3]
    tcp_len = (tcp_header[4] & 0xf000) >> 12
    tcp_reserved = (tcp_header[4] & 0x0e00) >> 9 
    tcp_ns = (tcp_header[4] & 0x0100) >> 8
    tcp_flags = tcp_header[4] & 0x0fff
    tcp_C = (tcp_header[4] & 0x0080) >> 7 
    tcp_E = (tcp_header[4] & 0x0040) >> 6
    tcp_U = (tcp_header[4] & 0x0020) >> 5
    tcp_A = (tcp_header[4] & 0x0010) >> 4
    tcp_P = (tcp_header[4] & 0x0008) >> 3
    tcp_R = (tcp_header[4] & 0x0004) >> 2
    tcp_S = (tcp_header[4] & 0x0002) >> 1
    tcp_F = tcp_header[4] & 0x0001
    tcp_window = tcp_header[5]
    tcp_checksum = hex(tcp_header[6])
    tcp_pointer = tcp_header[7]

    print("======tcp_header======")
    print("src_port:", tcp_src)
    print("dst_port:", tcp_dst)
    print("seq_num:", tcp_sNum)
    print("ack_num:", tcp_ack)
    print("header_len:", tcp_len)
    print("flags:", tcp_flags)
    print(">>>reserved:", tcp_reserved)
    print(">>>nonce:", tcp_ns)
    print(">>>cwr:", tcp_C)
    print(">>>ece:", tcp_E)
    print(">>>urgent:", tcp_U)
    print(">>>ack:", tcp_A)
    print(">>>push:", tcp_P)
    print(">>>reset:", tcp_R)
    print(">>>syn:", tcp_S)
    print(">>>fin:", tcp_F)
    print("window_size_value:", tcp_window)
    print("checksum:", tcp_checksum)
    print("urgent_pointer:", tcp_pointer)

'''udp header'''
def parsing_udp_header(data):
    udp_header = struct.unpack("!4H", data)
    udp_src = udp_header[0]
    udp_dst = udp_header[1]
    udp_len = udp_header[2]
    udp_checksum = hex(udp_header[3])

    print("======udp_header======")
    print("src_port:", udp_src)
    print("dst_port:", udp_dst)
    print("leng:", udp_len)
    print("header checksum:", udp_checksum)


while True:
    print("<<<<<<Packet Capture Start>>>>>>")
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    ip_protocol = parsing_ip_header(data[0][14:34])
    if ip_protocol == 17:
        parsing_udp_header(data[0][34:42])
    else :
        parsing_tcp_header(data[0][34:54])


