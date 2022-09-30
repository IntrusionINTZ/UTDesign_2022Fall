# Intrusion UTDesign Project - Fall 2022


# Collected Data 
Windows, Mac OS and Linux data are available at the moment. Data is collected from a bunch of sources, including our personal laptops (Windows, MacOS) and from the datasets supplied by Dr. Ricks (mainly Linux). More data will be collected as we go.

# Objective 2: Fingerprinting OS using PCAP files

As a first step towards solving objective 2, we have written a short Python script which utilizes pyshark to parse internet-bound packets.

### Prerequisites:

* [Python](https://www.python.org/downloads/)
* PCAP files collected from a known machine

### Usage: 
`git clone https://github.com/IntrusionINTZ/UTDesign_2022Fall.git`

`cd UTDesign_2022Fall`

`python parser_scripts/parse_pcap.py {PCAP_FILE} {KNOWN_HOST_DEVICE} {OUTPUT_CSV_FILE}`

The script takes three arguments:
* *PCAP_FILE*: path to raw PCAP file to be analyzed
* *KNOWN_HOST_DEVICE*: Device name of the machine that we *know* the pcap files are taken from
* *OUTPUT_FILE_CSV*: Path to a csv file where we want the parsed output

Example:
`python parser_scripts/parse_pcap.py collected_data/windows/vxp_windows-pcapdata.pcapng windows parsed_data/Parsed_vxp_windows.csv`

Example output after running the script for the above PCAP file can be found in `parsed_data/Parsed_vxp_windows.csv`

### Next Steps:
* Research into which attributes within TCP or UDP layers can be useful for fingerprinting OS
* Further research into sub-layers like QUIC, TLS etc. and their attributes that can be used for fingerprinting OS
* Research into Data Analysis techniques to utilize our parsed data
