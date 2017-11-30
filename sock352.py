# CS 352 project part 2
# this is the initial socket library for project 2
# You wil need to fill in the various methods in this
# library

# main libraries
import binascii
import socket as syssock
import struct
import sys
import random

# encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame
from inspect import currentframe, getframeinfo

SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0x0A
SOCK352_FLAG = 0x05
global gBuffer
gBuffer = ""
MAX_WINDOW_SIZE = 32000
port = -1
recv = -1
sock = (0, 0)
address = ""
curr = 0
sock352PktHdrData = "!BBBBHHLLQQLL"
version = 0x1
protocol = 0x0
checksum = 0x0
source_port = 0x0
dest_port = 0x0
window = 0x0
header_len = 40
data = ""

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages
global sock352portTx
global sock352portRx
# the public and private keychains in hex format
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

global box
global secretkey
global addressPkey
global defaultSKey
global defaultPKey

secretkey = -1
addressPkey = -1
defaultSKey = -1
defaultPKey = -1

# this is the structure of the sock352 packet
# sock352HdrStructStr = '!BBBBHHLLQQLL'


def init(UDPportTx, UDPportRx):  # initialize your UDP socket here
    global sock, port, recv
    # create the socket
    sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    recv = int(UDPportRx)
    # checks if empty
    if(UDPportTx == ''):
        port = recv
    else:
        # creates the port
        port = int(UDPportTx)
        # binds the socket to the port
    sock.bind(('', recv))
    # sets the timeout
    sock.settimeout(.2)
    return


# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex, privateKeysHex, publicKeys, privateKeys
    global defaultSKey, defaultPKey

    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ((len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    if(host == 'localhost'):
                        host = '127.0.0.1'
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(
                            keyInHex, nacl.encoding.HexEncoder)
                        if(host == '*' and port == '*'):
                            defaultSKey = privateKeys[(host, port)]
                    elif (words[0] == "public"):
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(
                            keyInHex, nacl.encoding.HexEncoder)
                        if(host == '*' and port == '*'):
                            defaultPKey = publicKeys[(host, port)]
        except Exception, e:
            print("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print("error: No filename presented")
    return (publicKeys, privateKeys)


class socket:

    def __init__(self):
        # your code goes here
        return

    def bind(self, address):
        # bind is not used in this assignment
        return

    def connect(self, *args):

        global sock352portTx, ENCRYPT, sock, curr, box, recv
        global publicKeys, defaultPKey, addressPkey, secretkey, defaultSKey
        address = []
        # example code to parse an argument list
        if (len(args) >= 1):
            address = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True

        # current sequence number set to a random int
        curr = int(random.randint(10, 100))
        # create the header
        header = self.packetHeader(0x0, SOCK352_SYN, curr, 0, 0)
        ACKFlag = -1
        # create the packet
        while(ACKFlag != curr):
            sock.sendto(header, (address[0], port))
            newHeader = self.packet()
            ACKFlag = newHeader[9]
            window = newHeader[10]
        # connect
        sock.connect((address[0], port))
        curr += 1

        self.encrypt = False
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True
                if(address[0] == 'localhost'):
                    address = ('127.0.0.1', str(recv))
                for private_address in privateKeys:
                    if(private_address == (address[0], str(recv))):
                        secretkey = privateKeys[private_address]
                        break
                if(secretkey == -1):
                    secretkey = defaultSKey
                if(secretkey == -1):
                    print("Error no private key found")
                    return

                for public_address in publicKeys:
                    if(public_address == (address[0], str(port))):
                        addressPkey = publicKeys[public_address]
                        break
                if(addressPkey == -1):
                    addressPkey = defaultPKey
                if(addressPkey == -1):
                    print("Error no public key")
                    return
                box = Box(secretkey, addressPkey)
            else:
                return
        return

    def listen(self, backlog):
        # listen is not used in this assignments
        pass
        return

    def accept(self, *args):
         # your code goes here
        global ENCRYPT, sock, recv, curr, box, recv
        global publicKeys, defaultPKey, addressPkey, secretkey, defaultSKey
        flag = -1
        newHeader = ""
        while(flag != SOCK352_SYN):
            # call packet until we get a new connection
            newHeader = self.packet()
            flag = newHeader[1]
        curr = newHeader[8]
        ####################
        # create a new header
        header = self.packetHeader(0x0, SOCK352_ACK, 0, curr, 13)
        ##################
        sock.sendto(header + "accepted", address)
        print('Connecting')
        self.encryption = False
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
                otherHost = (address[0], str(address[1]))
                for private_address in privateKeys:
                    if(private_address == ('127.0.0.1', str(recv))):
                        secretkey = privateKeys[private_address]
                        break
                if(secretkey == -1):
                    secretkey = defaultSKey
                if(secretkey == -1):
                    print("No private key found")
                    return (0, 0)
                for public_address in publicKeys:
                    if(public_address == otherHost):
                        addressPkey = publicKeys[public_address]
                        break
                if(addressPkey == -1):
                    addressPkey = defaultPKey
                if(addressPkey == -1):
                    print("No public key found")
                    return (0, 0)
                box = Box(secretkey, addressPkey)
            else:
                return
        curr += 1
        clientsocket = socket()
        return (clientsocket, address)

    def close(self):
        # your code goes here
        temp = random.randint(10, 100)
        ###################
        # create a new header
        header = self.packetHeader(0x0, SOCK352_FIN, temp, 0, 0)
        ####################
        # sets the timeout and waits to see if theres a FIN packet
        ACKFlag = -1
        counter = 0
        while(ACKFlag != temp):
            counter += 1
            if(counter > 4):
                print("Connection closed by other host")
                break
            try:
                sock.sendto(header, address)
            except TypeError:
                sock.send(header)
            newHeader = self.packet()
            ACKFlag = newHeader[9]
        sock.close()
        print("Connection closed")
        return

    def send(self, buffer):
        # your code goes here
        global sock, header_len, curr, box, window

        bytessent = 0
        messageLength = len(buffer)
        while(messageLength > 0):
            # Take the top 255 bytes of the message because
            # thats the max payload we represent with a "B"
            ######################
            # create a new header
            length = 65500
            while(window < 1):
                newHeader = self.packet()
                window = newHeader[10]
            if(messageLength > window):
                messageLength = window
            bit = 0x0
            filler = 0
            message = ""
            if(self.encrypt):
                filler = 40
                length = length - filler
                message = buffer[:length]
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                message = box.encrypt(message, nonce)
                bit = 0x1
            else:
                message = buffer[:length]
            messageHeader = self.packetHeader(bit, 0x03, curr, 0, length)
            totalSent = 0
            ACKFlag = -1
            newWindow = 01
            while(ACKFlag != curr):
                totalSent = sock.send(
                    messageHeader + message) - header_len - filler
                newHeader = self.packet()
                ACKFlag = newHeader[9]
                window = newHeader[10]
            window = newWindow
            messageLength -= length
            buffer = buffer[length:]
            bytessent += totalSent
            curr += 1
        print("Bytes sent = %d" % bytessent)
        return bytessent

    def recv(self, nbytes):
        # your code goes here
        global sock, data, curr, window, gBuffer

        data = ""
        bytesreceived = ""
        print("\tReceiving %d bytes" % (nbytes))
        while(nbytes > 0):
            if(len(gBuffer) >= nbytes):
                bytesreceived += gBuffer[:nbytes]
                gBuffer = gBuffer[nbytes:]
                window += nbytes
                nbytes = 0
                newHeader = self.packet()
                seq_no = newHeader[8]
                if(seq_no == curr):
                    if(newHeader[2] == 0x1):
                        data = box.decrypt(data)
                    window -= len(data)
                    gBuffer += data
                    curr += 1
                header = self.packetHeader(0x0, 0x04, 0, seq_no, 0)
                print seq_no
                sock.sendto(header, address)
                continue
            bytesreceived += gBuffer
            nbytes -= len(gBuffer)
            gBuffer = ""
            window = MAX_WINDOW_SIZE
            seq_no = -1
            # Keep checking the incoming packets until we get
            # one with the sequence number we specified eralier
            while(seq_no != curr):
                newHeader = self.packet()
                seq_no = newHeader[8]
                if(seq_no == curr):
                    if(newHeader[2] == 0x1):
                        data = box.decrypt(data)
                    window -= len(data)
                ###############
                # create new header
                header = self.packetHeader(0x0, SOCK352_ACK, 0, seq_no, 0)
                sock.sendto(header, address)
            gBuffer += data

            curr += 1
        print("Finished receiving the specified amount.")
        return bytesreceived

    # Packet class
    def packet(self):
        global sock, sock352PktHdrData, address, data
        # attempts to recv packet if not will print error message
        try:
            (data, dest) = sock.recvfrom(65536)
        except syssock.timeout:
            print("No packets received, timeout window maxed")
            head = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            return head
        # unpacks the packet
        (data_header, data_msg) = (data[:40], data[40:])
        header = struct.unpack(sock352PktHdrData, data_header)
        flag = header[1]

        # checks serveral flag conditions as listed in the specs
        if(flag == SOCK352_SYN):
            address = dest
            return header
        elif(flag == SOCK352_FIN):
            terminalHeader = self.packetHeader(
                0x0, SOCK352_ACK, 0, header[8], 0)
            sock.sendto(terminalHeader, dest)
            return header
        elif(flag == 0x03):
            data = data_msg
            return header
        elif(flag == SOCK352_ACK):
            return header
        elif(flag == SOCK352_RESET):
            return header
        else:
            header = self.packetHeader(
                0x0, SOCK352_RESET, header[8], header[9], 0)
            if(sock.sendto(header, dest) > 0):
                print("Sent a reset packet")
            else:
                print("Reset packet failed")
            return header
    # we found that we were repeating code a lot so decided to make a function out of it

    def packetHeader(self, bit, flag, seqNo, ackNo, payLoad):
        global sock352PktHdrData, header_len, version, protocol
        global checksum, source_port, dest_port, window

        opt_ptr = bit
        flags = flag
        sequence_no = seqNo
        ack_no = ackNo
        payload_len = payLoad
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        return udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol,
                                    header_len, checksum, source_port, dest_port, sequence_no,
                                    ack_no, window, payload_len)
