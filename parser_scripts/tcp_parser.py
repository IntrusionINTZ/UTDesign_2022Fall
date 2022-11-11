import sys
import pyshark
import os
from csv import DictWriter
import time


#A list of objects where each object is the parsed attributes from each packet
parsedPackets = []

def main():
        path = str(sys.argv[1])
        if os.path.isfile(path) and (path.endswith(".pcapng") or path.endswith(".pcap")):
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
                print ("ERROR: No TCP packets found in file")
                
#Performs preliminary parsing of the packet
def parsePacket(packet):   
        attributes = {}
        # windows_ip_list = ["192.168.2.241", "192.168.2.212", "192.168.2.95", "192.168.2.91"]
        # mac_ip_list = ["192.168.2.219"]
        
        if hasattr(packet, 'tcp'):
            parseTCPPacket(packet, attributes)
            return attributes
        else:
                return None

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


#Prints parsed packet data to parsed_packets.csv...
def printToCSV(parsedPackets, outputFileName):
        print("Printing parsed data to file: " + outputFileName)
        common_keys = {k for r in parsedPackets for k in r}
        output_file = open(outputFileName, 'a')
        with output_file as output:
                        writer = DictWriter(output, fieldnames=common_keys, restval="N/A")
                        writer.writeheader()
                        writer.writerows(parsedPackets)
        output_file.close()
        print("COMPLETE!")


if __name__ == '__main__':
    main()