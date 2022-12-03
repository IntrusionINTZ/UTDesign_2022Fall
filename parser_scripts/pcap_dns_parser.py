import pyshark
import pickle
import sys

# use: python pcap_dns_parser.py [pcap file]

# driver method main
def main():
    capture = pyshark.FileCapture(str(sys.argv[1]))
    dnsPackets = set()
    for packet in capture:
        try:
            dnsPackets.add(packet.dns.qry_name)
        except:
            None

    # dictionary of Operating System and list of hostnames associated with the OS
    file = open('osProfiles.p', 'rb')
    osDictionary = pickle.load(file)
    file.close()

    # comparing known OS hostnames against unique hostnames of unknown PCAP file
    analyzedList = []
    for operatingSystem, address_list in osDictionary.items():
        overlap = set(address_list).intersection(dnsPackets)
        print("overlap :", operatingSystem , "\t", overlap)
        analyzedList.append([operatingSystem, len(overlap)])

    finalList = (sorted(analyzedList, key=lambda x: x[1]))
    if finalList[-1][1] is 0:
        print("inconclusive results")
    else: 
        print("Predicted Operating System: \t\t", finalList[-1][0])
        print("Second Predicted Operating System: \t", finalList[-2][0])
    
    printout = input("Enter 1 if dns packet list needed ")
    if printout is "1":
        print(dnsPackets)



if __name__ == '__main__':
    main()
