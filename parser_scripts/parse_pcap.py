import sys
import pyshark
import os
from csv import DictWriter
import time


#A list of objects where each object is the parsed attributes from each packet
parsedPackets = []

def main():

        path = str(sys.argv[1])
        if os.path.isfile(path) and path.endswith(".pcapng"):
                parseFile(path)

        elif os.path.isdir(path):
                parseDirectory(path)

        #Print final list to the csv file name provided as argument
        printToCSV(parsedPackets, str(sys.argv[3]))

                

def parseDirectory(directory):
        print("Reading from directory: " + directory)
        dir = os.fsencode(directory)
    
        for file in os.listdir(dir):
                filename = os.fsdecode(file)
                if filename.endswith(".pcapng"): 
                        parseFile(str(directory + "\\" + filename))
                        time.sleep(5)
                        continue
                else:
                        continue

def parseFile(file):
        print("Reading from file: " + file)
        #Capture packet objects from a pcapng file
        capture = pyshark.FileCapture(os.path.join(os.getcwd(), file))

        #Parse each internet-bound packet into an object that has all relevant attributes to OS fingerprinting
        for packet in capture:
                parsedAttrs = parsePacket(packet)
                if parsedAttrs != None: #parsePacket() will return None if packet is not internet-bound packet
                        parsedPackets.append(parsedAttrs) 

        #Display error message if no internet-bound packets found throughout the dataset
        if len(parsedPackets) == 0:
                print ("ERROR: No Internet Bound packets found in file")
                
#Performs preliminary parsing of the packet
def parsePacket(packet):   
        attributes = {}
        if hasattr(packet, 'ip'): #Continue to parse further layers only if IP Layer is found, else return None.
                parseIPLayer(packet, attributes)
                if hasattr(packet, 'tcp'):
                        parseTCPPacket(packet, attributes)
                if hasattr(packet, 'udp'):
                        parseUDPPacket(packet, attributes)
                if hasattr(packet, 'tls'):
                        parseTLSPacket(packet, attributes)
                if hasattr(packet, 'http'):
                        parseHTTPPacket(packet, attributes)
                return attributes
        else:
                return None

#Parses the IP Layer of the packet     
def parseIPLayer(packet, attributes):
        attributes.update({
        'PACKET_NO': packet.number,
        'KNOWN_HOST_DEVICE': str(sys.argv[2]),
        'DST_IP': packet.ip.dst_host,
        'SRC_IP': packet.ip.src_host,
        'PACKET_SIZE': packet.ip.hdr_len,
        'TIMESTAMP': packet.sniff_timestamp,
        'TTL': packet.ip.ttl,
        'DF_FLAG': packet.ip.flags_df,
        'MF_FLAG': packet.ip.flags_mf,
        'IP_FRAG_OFF': packet.ip.frag_offset,
        })

#WIP: Parses the transport Layer of a TCP packet
def parseTCPPacket(packet, attributes):
        attributes.update({
                'PROTOCOL': 'tcp',
                'SRC_PORT': packet.tcp.srcport,
                'DST_PORT': packet.tcp.dstport,
                'TCP_HDR_LEN': packet.tcp.hdr_len,
                'TCP_FLAGS': packet.tcp.flags_str,
                'TCP_SEQ': packet.tcp.seq_raw,
                'TCP_ACK': packet.tcp.ack,
                'TCP_URP': packet.tcp.urgent_pointer,
                'TCP_WINDOW_SIZE': packet.tcp.window_size_value,
        })

        if hasattr(packet.tcp, 'options'):
                attributes.update({
                'TCP_OPTIONS': packet.tcp.options,
                })

#WIP: Parses the transport Layer of a UDP packet
def parseUDPPacket(packet, attributes):
        attributes.update({
                'PROTOCOL': 'udp',
                'SRC_PORT': packet.udp.srcport,
                'DST_PORT': packet.udp.dstport
        })

#WIP: Parses an HTTP Packet 
def parseHTTPPacket(packet, attributes):
        try: 
                packet.http.user_agent
        except:
                return
        attributes.update({
                'SUB_PROTOCOL': 'http',
                'HTTP_USER_AGENT': packet.http.user_agent
        })

#WIP: Parses a TLS packet
def parseTLSPacket(packet, attributes):
        try:
                packet.tls.handshake
        except:
                return 
        if "Client Hello" in packet.tls.handshake:
                attributes.update({
                'SUB_PROTOCOL': 'tls',
                'TLS_VERSION': packet.tls.record_version,
                'TLS_CIPHER_SUITES': packet.tls.handshake_ciphersuites,
                'TLS_CIPHER_SUITES': packet.tls.handshake_ciphersuite,
                'TLS_EXTENSION_SIG_ALGS': packet.tls.handshake_sig_hash_alg,
                })

#Prints parsed packet data to parsed_packets.csv...
def printToCSV(parsedPackets, outputFileName):
        print("Printing parsed data to file: " + outputFileName)
        common_keys = {k for r in parsedPackets for k in r}
        with open(outputFileName, 'a') as output:
                        writer = DictWriter(output, fieldnames=common_keys, restval="N/A")
                        writer.writeheader()
                        writer.writerows(parsedPackets)
        print("COMPLETE!")


if __name__ == '__main__':
    main()