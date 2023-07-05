"""
Richard John Pecson Jr.
Marissa Ann Villaceran
NSCOM01 S12
"""

import socket, struct, os, sys

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

# TFTP default block size, port number, and timeout values
DEFAULT_BLOCK_SIZE = 512
DEFAULT_TIMEOUT = 5
DEFAULT_PORT = 69


def create_packet_rrq(filename, mode):
    """
    Create a RRQ (read request) packet.
    Type   Op #     Format without header
           2 bytes    string   1 byte     string   1 byte
            -----------------------------------------------
    RRQ    | 01 |  Filename  |   0  |    Mode    |   0  |
            -----------------------------------------------
    struct.pack("!H", OP_RRQ) packs the opcode value as an unsigned short (2 bytes) in network byte order.
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
    struct.pack("!H", OP_WRQ) packs the opcode value as an unsigned short (2 bytes) in network byte order.
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
    # Unpacks the first 2 bytes of the packet
    opcode = struct.unpack("!H", packet[:2])[0]

    if opcode == OP_RRQ or opcode == OP_WRQ:
        # splits packet, starting from the third byte (index 2)
        parts = packet[2:].split(b"\x00")
        # byte strings are decoded into string
        filename = parts[0].decode()
        mode = parts[1].decode()
        return opcode, (filename, mode)

    elif opcode == OP_DATA:
        block_number = struct.unpack("!H", packet[2:4])[0]
        # extracts the data content
        # data starts from index 4 of the packet.
        data = packet[4:]
        return opcode, (block_number, data)

    elif opcode == OP_ACK:
        block_number = struct.unpack("!H", packet[2:4])[0]
        return opcode, block_number

    elif opcode == OP_ERROR:
        error_code = struct.unpack("!H", packet[2:4])[0]
        # error message starts from index 4 of the packet
        # ends at the second-to-last byte of the packet (-1 index).
        error_message = packet[4:-1].decode()
        return opcode, (error_code, error_message)


def tftp_server(server_ip, root_dir=".", mode=MODE_OCTET, block_size=DEFAULT_BLOCK_SIZE, timeout=DEFAULT_TIMEOUT):
    """
    Run a TFTP server.

    :param server_ip: represents the IP address or hostname
                      specifies the network location where the TFTP server is running

    :param root_dir: default value of "." (the current directory)
                     specify the directory from which the TFTP server should serve files

    :param mode: represents the TFTP transfer mode
                 default value of MODE_OCTET

    :param block_size: block size for data packets during file transfer
                       default value of DEFAULT_BLOCK_SIZE

    :param timeout: timeout duration

    """

    # Create a UDP socket
    # creates a socket for IPv4 addressing (AF_INET) and using the UDP protocol (SOCK_DGRAM)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # created socket object
    sock.bind((server_ip, DEFAULT_PORT))
    print("Server has been created at {}:{}".format(server_ip, DEFAULT_PORT))

    while True:
        # 516 bytes, consists of 2 bytes for the opcode, 2 bytes for the block number, and up to 512 bytes for the data payload.
        # recvfrom() returns two values: the received packet and the address from which it was sent.
        # packet: received packet data assigned to it
        # (client_ip, client_port): address from which the packet was sent is unpacked
        #                           variables represent the client's IP address and port number.
        packet, (client_ip, client_port) = sock.recvfrom(block_size + 4)
        # return value of the parse_packet function is unpacked into two variables: opcode and payload
        opcode, payload = parse_packet(packet)

        # If operation code is for Read Request
        if opcode == OP_RRQ:
            filename, mode = payload
            # complete local file path that combines the root_dir and filename
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
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <server_ip> [-r root_dir] [-s block_size]")
        sys.exit(1)

    server_ip = sys.argv[1] #use 0.0.0.0 muna since connectionless pa naman
    root_dir = "."
    block_size = DEFAULT_BLOCK_SIZE

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "-r" and i + 1 < len(sys.argv):
            root_dir = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "-s" and i + 1 < len(sys.argv):
            block_size = int(sys.argv[i + 1])
            i += 2
        else:
            print(f"Usage: {sys.argv[0]} <server_ip> [-r root_dir] [-s block_size]")
            sys.exit(1)

    tftp_server(server_ip, root_dir, block_size=block_size)