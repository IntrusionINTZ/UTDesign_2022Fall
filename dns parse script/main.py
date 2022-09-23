import pyshark
import os
import pickle


# driver method main
def main():
    capture = pyshark.FileCapture(os.path.join(os.getcwd(), 'example_pcap.pcapng'))
    dnsPackets = set()
    for packet in capture:
        destination_address = packet.ip.dst
        if destination_address:
            dnsPackets.add(destination_address)

    # DNS destinations not unique to Operating System
    file = open('/Users/alarikavoora/PycharmProjects/broadwayTechnology/dnsDestinations.txt', 'rb')
    commonDNSDestinations = pickle.load(file)
    file.close()

    # remove common hostnames from DNS list
    uniqueDNSList = set([x for x in dnsPackets if x not in commonDNSDestinations])

    # dictionary of Operating System and list of hostnames associated with the OS
    file = open('/Users/alarikavoora/PycharmProjects/broadwayTechnology/osProfiles.txt', 'rb')
    osDictionary = pickle.load(file)
    file.close()

    # comparing known OS hostnames against unique hostnames of unknown PCAP file
    analyzedList = []
    for operatingSystem, address_list in osDictionary.items():
        overlap = set(address_list) & uniqueDNSList
        percentage = float(len(overlap)) / len(address_list) * 100
        analyzedList.append([operatingSystem, percentage])

    finalList = (sorted(analyzedList, key=lambda x: x[1]))
    print(finalList)


if __name__ == '__main__':
    main()
