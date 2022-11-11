import sys
import pyshark
import os
from csv import DictWriter
import time


def main():

        path = str(sys.argv[1])
        os = str(sys.argv[2])
        outputFile = str(sys.argv[3])
        requiredProtocol = str(sys.argv[4])

        parser = PCAPParser(path, os, outputFile, requiredProtocol)
        

        parser.parse()
        parser.printToCSV()


class PCAPParser:
    def __init__(self, path, os, outputFile, requiredProtocol = "all"):
        self.path = path
        self.os = os
        self.outputFile = outputFile
        self.attributes = {}
        self.parsedPackets = []
        self.requiredProtocol = requiredProtocol


    def parse(self):
        if os.path.isfile(self.path) and self.path.endswith(".pcapng"):
                self.parseFile(self.path)

        elif os.path.isdir(self.path):
                self.parseDirectory(self.path)

    
    def parseFile(self, file):
        print("Reading from file: " + file)
        #Capture packet objects from a pcapng file
        capture = pyshark.FileCapture(os.path.join(os.getcwd(), file))

        #Parse each internet-bound packet into an object that has all relevant attributes to OS fingerprinting
        for packet in capture:
                parsedAttrs = self.parsePacket(packet)
                if parsedAttrs != None: #parsePacket() will return None if packet is not internet-bound packet
                        self.parsedPackets.append(parsedAttrs)

        #Display error message if no internet-bound packets found throughout the dataset
        if len(self.parsedPackets) == 0:
                print ("ERROR: No Internet Bound packets found in file")

    def parseDirectory(self, directory):
        print("Reading from directory: " + directory)
        dir = os.fsencode(directory)
    
        for file in os.listdir(dir):
                filename = os.fsdecode(file)
                if filename.endswith(".pcapng"): 
                        self.parseFile(str(os.path.join(os.getcwd(), filename)))
                        time.sleep(5)
                        continue
                else:
                        continue

    #Performs preliminary parsing of the packet
    def parsePacket(self, packet):
        self.attributes = {}
        if hasattr(packet, 'ip'): #Continue to parse further layers only if IP Layer is found, else return None.
                self.parseIPLayer(packet)
                if hasattr(packet, 'tcp') and self.requiredProtocol in ("all", "tcp"):
                        self.parseTCPPacket(packet)
                if hasattr(packet, 'udp') and self.requiredProtocol in ("all", "udp"):
                        self.parseUDPPacket(packet)
                if hasattr(packet, 'tls') and self.requiredProtocol in ("all", "tls"):
                        self.parseTLSPacket(packet)
                if hasattr(packet, 'http') and self.requiredProtocol in ("all", "http"):
                        self.parseHTTPPacket(packet)
                return self.attributes
        else:
                return None

    #Parses the IP Layer of the packet     
    def parseIPLayer(self, packet):
        self.attributes.update ({
        'PACKET_NO': packet.number,
        'KNOWN_HOST_DEVICE': self.os,
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
    def parseTCPPacket(self, packet):
        self.attributes.update ({
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
                self.attributes.update({
                'TCP_OPTIONS': packet.tcp.options,
                })

    #WIP: Parses the transport Layer of a UDP packet
    def parseUDPPacket(self, packet):
        self.attributes.update({
                'PROTOCOL': 'udp',
                'SRC_PORT': packet.udp.srcport,
                'DST_PORT': packet.udp.dstport
        })

    #WIP: Parses an HTTP Packet 
    def parseHTTPPacket(self, packet):
        try: 
                packet.http.user_agent
        except:
                return
        self.attributes.update({
                'SUB_PROTOCOL': 'http',
                'HTTP_USER_AGENT': packet.http.user_agent
        })

    #WIP: Parses a TLS packet
    def parseTLSPacket(self, packet):
        try:
                packet.tls.handshake
        except:
                return 
        if "Client Hello" in packet.tls.handshake:
                self.attributes.update({
                'SUB_PROTOCOL': 'tls',
                'TLS_VERSION': packet.tls.record_version,
                'TLS_CIPHER_SUITES': packet.tls.handshake_ciphersuites,
                'TLS_CIPHER_SUITES': packet.tls.handshake_ciphersuite,
                'TLS_EXTENSION_SIG_ALGS': packet.tls.handshake_sig_hash_alg,
                })

    #Prints parsed packet data to parsed_packets.csv...
    def printToCSV(self):
        print("Printing parsed data to file: " + self.outputFile)
        common_keys = {k for r in self.parsedPackets for k in r}
        with open(self.outputFile, 'a') as output:
                        writer = DictWriter(output, fieldnames=common_keys, restval="N/A")
                        writer.writeheader()
                        writer.writerows(self.parsedPackets)
        print("COMPLETE!")


if __name__ == '__main__':
    main()