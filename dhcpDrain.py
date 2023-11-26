import socket
import struct
import random
import sys
import time

def create_dhcp_discover():
    random_mac_address = generate_random_mac_address()
    mac_bytes = mac_address_to_bytes(random_mac_address)
    message = b''
    message += b'\x01'   # Message type: Boot Request (1)
    message += b'\x01'   # Hardware type: Ethernet (1)
    message += b'\x06'   # Hardware address length: 6
    message += b'\x00'   # Hops: 0
    message += b'\x39\x03\xF3\x26' # Random transaction ID
    message += b'\x00\x00' # Seconds elapsed: 0
    message += b'\x80\x00' # Bootp flags: 0x8000 (Broadcast) + reserved flags
    message += b'\x00\x00\x00\x00' # Client IP address: 0.0.0.0
    message += b'\x00\x00\x00\x00' # Your (client) IP address: 0.0.0.0
    message += b'\x00\x00\x00\x00' # Next server IP address: 0.0.0.0
    message += b'\x00\x00\x00\x00' # Relay agent IP address: 0.0.0.0
    message += mac_bytes # Client MAC address
    message += b'\x00' * 10  # Padding for client MAC address
    message += b'\x00' * 67  # Server host name not given
    message += b'\x00' * 125 # Boot file name not given
    message += b'\x63\x82\x53\x63'   # Magic cookie: DHCP
    message += b'\x35\x01\x01'       # Option: (t=53,l=1) DHCP Discover
    message += b'\xff'   # End Option
    return message

def listen_for_offer(sock):
    sock.settimeout(2)  # Set timeout to 10 seconds

    try:
        while True:
            message, address = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            if parse_dhcp_message(message, sock):
                break
    except socket.timeout:
        print("DHCP Scope Now Drained")
        sys.exit()
    except Exception as e:
        print(f"Error occurred: {e}")

def send_dhcp_discover():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', 68))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        discover_message = create_dhcp_discover()
        s.sendto(discover_message, ('255.255.255.255', 67))

        listen_for_offer(s)

    except Exception as e:
        print(f"Error sending DHCP Discover: {e}")

    finally:
        s.close()

def parse_dhcp_message(message,s):
    msg_type, hw_type, hw_addr_len, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr = struct.unpack('!BBBBIHHIIII', message[:28])

    transaction_id = xid  # Use the same transaction ID as in your DHCPDISCOVER
    offered_ip_address = int_to_ip(yiaddr)  # Replace with the IP offered in DHCPOFFER
    dhcp_server_ip = int_to_ip(siaddr)  # Replace with the IP of the DHCP server from DHCPOFFER



    mac_addr = ':'.join('%02x' % b for b in message[28:34])
    mac_str = mac_addr
    mac_bytes = mac_address_to_bytes(mac_str)

    options = message[240:]

    i = 0
    while i < len(options):
        option = options[i]
        length = options[i + 1]
        data = options[i + 2:i + 2 + length]
        if option == 53:  # DHCP Message Type
            msg_type = data[0]
            #print(f"DHCP Message Type: {msg_type} ({dhcp_message_type(msg_type)})")
            if msg_type == 2:
                print(f"Your (Client) IP Address: {int_to_ip(yiaddr)} Mac: {mac_str}")
                send_dhcp_request(transaction_id, mac_bytes, offered_ip_address, dhcp_server_ip,s)
            if msg_type == 5:
                #print("ACK RECV")
                return True
        i += 2 + length

def int_to_ip(int_val):
    return '.'.join(str(int_val >> (i * 8) & 0xFF) for i in reversed(range(4)))

def dhcp_message_type(type_val):
    types = {
        1: 'DHCPDISCOVER',
        2: 'DHCPOFFER',
        3: 'DHCPREQUEST',
        5: 'DHCPACK'
    }
    return types.get(type_val, 'Unknown')

def create_dhcp_request(xid, client_mac, offered_ip, server_ip):
    message = b'\x01'   # Message type: Boot Request (1)
    message += b'\x01'   # Hardware type: Ethernet (1)
    message += b'\x06'   # Hardware address length: 6
    message += b'\x00'   # Hops: 0
    message += struct.pack('!I', xid)  # Transaction ID
    message += b'\x00\x00' # Seconds elapsed: 0
    message += b'\x00\x00' # Bootp flags: Unicast
    message += b'\x00\x00\x00\x00' # Client IP address: 0.0.0.0 (since the client doesn't have an IP yet)
    message += b'\x00\x00\x00\x00' # Your (client) IP address: 0.0.0.0
    message += b'\x00\x00\x00\x00' # Next server IP address: 0.0.0.0
    message += b'\x00\x00\x00\x00' # Relay agent IP address: 0.0.0.0
    message += client_mac
    message += b'\x00' * (16 - len(client_mac))  # Padding for client MAC address
    message += b'\x00' * 64  # Server host name not given
    message += b'\x00' * 128 # Boot file name not given
    message += b'\x63\x82\x53\x63'   # Magic cookie: DHCP
    message += b'\x35\x01\x03'       # Option: (53, 1, DHCPREQUEST)
    message += b'\x32\x04' + socket.inet_aton(offered_ip) # Option: (50, 4, Requested IP Address)
    message += b'\x36\x04' + socket.inet_aton(server_ip)  # Option: (54, 4, DHCP Server Identifier)
    message += b'\xff'   # End Option
    return message

def send_dhcp_request(xid, client_mac, offered_ip, server_ip,s):
    try:

        request_message = create_dhcp_request(xid, client_mac, offered_ip, server_ip)
        s.sendto(request_message, ('255.255.255.255', 67))

    except Exception as e:
        print(f"Error sending DHCP Request: {e}")

def mac_address_to_bytes(mac_str):
    hex_str = mac_str.split(':')

    mac_bytes = bytes(int(h, 16) for h in hex_str)
    return mac_bytes


def generate_random_mac_address():
    random_mac = [random.randint(0, 255) for _ in range(6)]
    mac_address = ':'.join(f'{b:02x}' for b in random_mac)

    return mac_address

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))
    )[20:24])

while True:
    send_dhcp_discover()
    time.sleep(0.01)
