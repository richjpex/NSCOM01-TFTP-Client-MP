import socket, struct, sys, os

# TFTP packet opcodes
OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5

# TFTP transfer modes
MODE_NETASCII = "netascii"
MODE_OCTET = "octet"

# TFTP default block size and timeout values
DEFAULT_BLOCK_SIZE = 512
DEFAULT_TIMEOUT = 5

def create_packet_rrq(filename, mode):
    """
    Create a RRQ (read request) packet.
    Type   Op #     Format without header
            2 bytes    string   1 byte     string   1 byte
            -----------------------------------------------
    RRQ/   | 01 |  Filename  |   0  |    Mode    |   0  |
            -----------------------------------------------
    struct.pack("!H", OP_RRQ): packs the opcode value as an unsigned short (2 bytes) in network byte order.
    filename.encode() converts the filename string into bytes
    mode.encode() converts the mode string into bytes
    b"\x00": null byte

    """
    return struct.pack("!H", OP_RRQ) + filename.encode() + b"\x00" + mode.encode() + b"\x00"

def create_packet_wrq(filename, mode):
    """
    Create a WRQ (write request) packet.
    Type   Op #     Format without header
           2 bytes    string   1 byte     string   1 byte
            -----------------------------------------------
    WRQ    | 01 |  Filename  |   0  |    Mode    |   0  |
            -----------------------------------------------
    struct.pack("!H", OP_WRQ): packs the opcode value as an unsigned short (2 bytes) in network byte order.
    filename.encode() converts the filename string into bytes
    mode.encode() converts the mode string into bytes
    b"\x00": null byte

    """
    return struct.pack("!H", OP_WRQ) + filename.encode() + b"\x00" + mode.encode() + b"\x00"

def create_packet_data(block_number, data):
    """
    Create a DATA packet.

           2 bytes    2 bytes       n bytes
          ---------------------------------
   DATA  | 03    |   Block #  |    Data    |
          ---------------------------------
     data already byte because data = f.read(block_size) is in byte
    """
    return struct.pack("!HH", OP_DATA, block_number) + data

def create_packet_ack(block_number):
    """
    Create an ACK (acknowledgment) packet.
              2 bytes    2 bytes
             -------------------
      ACK   | 04    |   Block #  |
             --------------------
    """
    return struct.pack("!HH", OP_ACK, block_number)

def create_packet_error(error_code, error_message):
    """
    Create an ERROR packet.

      2 bytes  2 bytes        string    1 byte
          ----------------------------------------
   ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
          ----------------------------------------

    """
    return struct.pack("!HH", OP_ERROR, error_code) + error_message.encode() + b"\x00"

def parse_packet(packet):
    """
    Parse a TFTP packet and return its opcode and payload.
    """
    opcode = struct.unpack("!H", packet[:2])[0]
    
    if opcode == OP_RRQ or opcode == OP_WRQ:
        parts = packet[2:].split(b"\x00")
        filename = parts[0].decode()
        mode = parts[1].decode()
        return opcode, (filename, mode)
    
    elif opcode == OP_DATA:
        block_number = struct.unpack("!H", packet[2:4])[0]
        data = packet[4:]
        return opcode, (block_number, data)
    
    elif opcode == OP_ACK:
        block_number = struct.unpack("!H", packet[2:4])[0]
        return opcode, block_number
    
    elif opcode == OP_ERROR:
        error_code = struct.unpack("!H", packet[2:4])[0]
        error_message = packet[4:-1].decode()
        return opcode, (error_code, error_message)
    
def tftp_client_get(server_ip, server_port, filename, local_filename=None, mode=MODE_OCTET, block_size=DEFAULT_BLOCK_SIZE, timeout=DEFAULT_TIMEOUT):
    """
    Download a file from a TFTP server.
    """
    if local_filename is None:
        local_filename = filename
    
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    # Send RRQ packet
    rrq_packet = create_packet_rrq(filename, mode)
    sock.sendto(rrq_packet, (server_ip, server_port))
    
    # Receive DATA packets and send ACK packets
    with open(local_filename, "wb") as f:
        block_number = 1
        while True:
            try:
                packet, (server_ip, server_port) = sock.recvfrom(block_size + 4)
            except socket.timeout:
                print("Timeout waiting for server response")
                return
            
            opcode, payload = parse_packet(packet)
            
            if opcode == OP_DATA:
                recv_block_number, data = payload
                
                if recv_block_number == block_number:
                    f.write(data)
                    ack_packet = create_packet_ack(block_number)
                    sock.sendto(ack_packet, (server_ip, server_port))
                    block_number += 1
                    
                    if len(data) < block_size:
                        break
                
                elif recv_block_number < block_number:
                    ack_packet = create_packet_ack(recv_block_number)
                    sock.sendto(ack_packet, (server_ip, server_port))
            
            elif opcode == OP_ERROR:
                error_code, error_message = payload
                print(f"Error {error_code}: {error_message}")
                return

def tftp_client_put(server_ip, server_port, filename, local_filename=None, mode=MODE_OCTET, block_size=DEFAULT_BLOCK_SIZE, timeout=DEFAULT_TIMEOUT):
    """
    Upload a file to a TFTP server.
    """
    if local_filename is None:
        local_filename = filename
    
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    # Send WRQ packet
    wrq_packet = create_packet_wrq(filename, mode)
    sock.sendto(wrq_packet, (server_ip, server_port))
    
    # Receive ACK packets and send DATA packets
    with open(local_filename, "rb") as f:
        block_number = 1
        while True:
            try:
                packet, (server_ip, server_port) = sock.recvfrom(block_size + 4)
            except socket.timeout:
                print("Timeout waiting for server response")
                return
            
            opcode, payload = parse_packet(packet)
            
            if opcode == OP_ACK:
                recv_block_number = payload
                
                if recv_block_number == block_number:
                    data = f.read(block_size)
                    data_packet = create_packet_data(block_number + 1, data)
                    sock.sendto(data_packet, (server_ip, server_port))
                    block_number += 1
                    
                    if len(data) < block_size:
                        break
            
            elif opcode == OP_ERROR:
                error_code, error_message = payload
                print(f"Error {error_code}: {error_message}")
                return

# in the main, ask the user to enter the server IP address, port number, and the file name to be downloaded or uploaded
# then call the appropriate function to download or upload the file
if __name__ == "__main__":
    server_ip = input("Server IP: ") #when testing, use 0.0.0.0
    server_port = int(input("Server port: ")) #when testing, use 69
    while True:

        command = input("Command (get/put/exit): ")
        if command == "exit":
            print("Goodbye!")
            sys.exit(0)

        elif command == "get" or command == "put":
            filename = input("Filename: ")
            
            if command == "get":
                tftp_client_get(server_ip, server_port, filename)
            
            elif command=="put":
                tftp_client_put(server_ip, server_port, filename)
        
        else:
            print("Invalid command")