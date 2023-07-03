import socket
import struct
import os
import sys
import time

# TFTP packet opcodes
OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5

# TFTP error codes
ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_NO_SUCH_USER = 7

# TFTP error messages
ERROR_MESSAGES = {
    ERR_NOT_DEFINED: "Not defined",
    ERR_FILE_NOT_FOUND: "File not found",
    ERR_ACCESS_VIOLATION: "Access violation",
    ERR_DISK_FULL: "Disk full or allocation exceeded",
    ERR_ILLEGAL_OPERATION: "Illegal TFTP operation",
    ERR_UNKNOWN_TID: "Unknown transfer ID",
    ERR_FILE_EXISTS: "File already exists",
    ERR_NO_SUCH_USER: "No such user"
}

# TFTP transfer modes
MODE_NETASCII = "netascii"
MODE_OCTET = "octet"

# TFTP default block size, port, and timeout values
DEFAULT_BLOCK_SIZE = 512
DEFAULT_TIMEOUT = 5


def create_packet_rrq(filename, mode):
    """
    Create a RRQ (read request) packet.
    """
    return struct.pack("!H", OP_RRQ) + filename.encode() + b"\x00" + mode.encode() + b"\x00"

def create_packet_wrq(filename, mode):
    """
    Create a WRQ (write request) packet.
    """
    return struct.pack("!H", OP_WRQ) + filename.encode() + b"\x00" + mode.encode() + b"\x00"

def create_packet_data(block_number, data):
    """
    Create a DATA packet.
    """
    return struct.pack("!HH", OP_DATA, block_number) + data

def create_packet_ack(block_number):
    """
    Create an ACK (acknowledgment) packet.
    """
    return struct.pack("!HH", OP_ACK, block_number)

def create_packet_error(error_code, error_message):
    """
    Create an ERROR packet.
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
    
def tftp_server(server_ip, server_port, root_dir=".", mode=MODE_OCTET, block_size=DEFAULT_BLOCK_SIZE, timeout=DEFAULT_TIMEOUT):
    """
    Run a TFTP server.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print("Server has been created at {}:{}".format(server_ip, server_port))
    
    while True:
        packet, (client_ip, client_port) = sock.recvfrom(block_size + 4)
        opcode, payload = parse_packet(packet)
        
        if opcode == OP_RRQ:
            filename, mode = payload
            local_filename = os.path.join(root_dir, filename)
            
            if not os.path.isfile(local_filename):
                error_packet = create_packet_error(ERR_FILE_NOT_FOUND, ERROR_MESSAGES[ERR_FILE_NOT_FOUND])
                sock.sendto(error_packet, (client_ip, client_port))
                continue
            
            with open(local_filename, "rb") as f:
                block_number = 1
                while True:
                    data = f.read(block_size)
                    data_packet = create_packet_data(block_number, data)
                    sock.sendto(data_packet, (client_ip, client_port))
                    
                    try:
                        packet, _ = sock.recvfrom(block_size + 4)
                    except socket.timeout:
                        print("Timeout waiting for client response")
                        break
                    
                    opcode, payload = parse_packet(packet)
                    
                    if opcode == OP_ACK:
                        recv_block_number = payload
                        
                        if recv_block_number == block_number:
                            block_number += 1
                            
                            if len(data) < block_size:
                                break
                    
                    elif opcode == OP_ERROR:
                        error_code, error_message = payload
                        print(f"Error {error_code}: {error_message}")
                        break
        
        elif opcode == OP_WRQ:
            filename, mode = payload
            local_filename = os.path.join(root_dir, filename)
            
            if os.path.isfile(local_filename):
                error_packet = create_packet_error(ERR_FILE_EXISTS, ERROR_MESSAGES[ERR_FILE_EXISTS])
                sock.sendto(error_packet, (client_ip, client_port))
                continue

            with open(local_filename, "wb") as f:
                block_number = 0
                while True:
                    ack_packet = create_packet_ack(block_number)
                    sock.sendto(ack_packet, (client_ip, client_port))
                    
                    try:
                        packet, _ = sock.recvfrom(block_size + 4)
                    except socket.timeout:
                        print("Timeout waiting for client response")
                        break
                    
                    opcode, payload = parse_packet(packet)
                    
                    if opcode == OP_DATA:
                        recv_block_number, data = payload
                        
                        if recv_block_number == block_number + 1:
                            block_number += 1
                            f.write(data)
                            
                            if len(data) < block_size:
                                break
                    
                    elif opcode == OP_ERROR:
                        error_code, error_message = payload
                        print(f"Error {error_code}: {error_message}")
                        break

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <server_ip> <server_port> [root_dir]")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    
    if len(sys.argv) > 3:
        root_dir = sys.argv[3]
    else:
        root_dir = "."
    
    tftp_server(server_ip, server_port, root_dir)