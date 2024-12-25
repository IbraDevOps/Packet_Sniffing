import socket
import struct
import textwrap


def main():
    # Create a raw socket to capture all network traffic
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)  # Capture packets
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # Parse IPv4 packets
        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print('\tIPv4 Packet:')
            print(f'\t\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\tProtocol: {proto}, Source: {src}, Target: {target}')

            # Parse transport layer
            if proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, offset, data = tcp_segment(data)
                print('\t\tTCP Segment:')
                print(f'\t\t\tSource Port: {src_port}, Destination Port: {dest_port}')
                print(f'\t\t\tSequence: {sequence}, Acknowledgment: {acknowledgment}')

            elif proto == 17:  # UDP
                src_port, dest_port, size, data = udp_segment(data)
                print('\t\tUDP Segment:')
                print(f'\t\t\tSource Port: {src_port}, Destination Port: {dest_port}, Length: {size}')

            elif proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\t\tICMP Packet:')
                print(f'\t\t\tType: {icmp_type}, Code: {code}, Checksum: {checksum}')


# Parse Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Convert MAC address to readable format
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))


# Parse IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Convert IPv4 addresses to readable format
def ipv4(addr):
    return '.'.join(map(str, addr))


# Parse TCP segments
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]


# Parse UDP segments
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Parse ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Format multi-line data for readability
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size += 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    main()
