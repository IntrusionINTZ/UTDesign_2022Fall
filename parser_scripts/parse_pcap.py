import sys
import pyshark
import os
from csv import DictWriter

def main():

        print("Reading from: " + str(sys.argv[1]))
        #Capture packet objects from a pcapng file
        capture = pyshark.FileCapture(os.path.join(os.getcwd(), str(sys.argv[1])))

        #A list of objects where each object is the parsed attributes from each packet
        parsedPackets = []

        #Parse each internet-bound packet into an object that has all relevant attributes to OS fingerprinting
        for packet in capture:
                parsedAttrs = parsePacket(packet)
                if parsedAttrs != None: #parsePacket() will return None if packet is not internet-bound packet
                        parsedPackets.append(parsedAttrs) 

        #Display error message if no internet-bound packets found throughout the dataset
        if len(parsedPackets) == 0:
                print ("ERROR: No Internet Bound packets found")
                exit()

        #Print final list to the csv file name provided as argument
        printToCSV(parsedPackets, str(sys.argv[3]))

#Performs preliminary parsing of the packet
def parsePacket(packet):   
        attributes = {}
        if hasattr(packet, 'ip'): #Continue to parse further layers only if IP Layer is found, else return None.
                parseIPLayer(packet, attributes)
                if hasattr(packet, 'tcp'):
                        parseTCPLayer(packet, attributes)
                if hasattr(packet, 'udp'):
                        parseUDPLayer(packet, attributes)
                if hasattr(packet, 'tls'):
                        parseTLSLayer(packet, attributes)
                if hasattr(packet, 'quic'):
                        parseQUICLayer(packet, attributes)
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

#WIP: Parses the TCP Layer of a TCP packet
def parseTCPLayer(packet, attributes):
        attributes.update({
                'PROTOCOL': 'tcp',
                'SRC_PORT': packet.tcp.srcport,
                'DST_PORT': packet.tcp.dstport
        })

#WIP: Parses the UDP Layer of a UDP packet
def parseUDPLayer(packet, attributes):
        attributes.update({
                'PROTOCOL': 'udp',
                'SRC_PORT': packet.udp.srcport,
                'DST_PORT': packet.udp.dstport
        })

#WIP: Parses the QUIC Layer of a UDP packet if found
def parseQUICLayer(packet, attributes):
        attributes.update({
                'SUB_PROTOCOL': 'quic',
        })

#WIP: Parses the TLS Layer of a packet if found
def parseTLSLayer(packet, attributes):
        attributes.update({
                'SUB_PROTOCOL': 'tls',
        })

#Prints parsed packet data to parsed_packets.csv...
def printToCSV(parsedPackets, outputFileName):
        print("Printing parsed data to file: " + outputFileName)
        with open(outputFileName, 'w') as output:
                        writer = DictWriter(output, fieldnames=parsedPackets[0].keys())
                        writer.writeheader()
                        writer.writerows(parsedPackets)
        print("COMPLETE!")


if __name__ == '__main__':
    main()