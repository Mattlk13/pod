#!/usr/bin/env python

"""
"""
import dpkt
import datetime
import socket
import json
import argparse


def read_config(cfg_file):
    with open(cfg_file) as f:
        return json.load(f)

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address: the string representation of a MAC address
    Returns:
        printable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)

def filter_packets(pcap, config):

    f_output = open(config["output_file"], "w") 

    lens = []
    is_first = True
    # For each packet in the pcap process the contents
    for ts, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # Now unpack the data within the Ethernet frame (the IP packet) 
        # Pulling out src, dst, length, fragment info, TTL, and Protocol

        size = len(buf)

        if size>100 and size not in lens:
            lens.append(size)

        if size in config["send"]["size"] \
            or (size >= config["recv"]["size"][0] \
             and size <= config["recv"]["size"][1]):
            pass
        else:
            continue
        
        ip = eth.data
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        if ip_src == config["send"]["source"] and ip_dst == config["send"]["destination"]:
            if is_first :
                f_output.write('%.9f' % ts)
                is_first = False
            else:
                f_output.write('\n%.9f' % ts)
        elif ip_src == config["recv"]["source"] and ip_dst == config["recv"]["destination"]:
            f_output.write('\t%.9f' % ts)

        # Print out the ts in UTC
        # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        # print 'Timestamp: ', int(ts)
        # print hw_ts
    
    f_output.write('\n')

    print(lens)

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="config file", default="pod_fema.cfg")
    args = parser.parse_args()
    
    config = read_config(args.config)

    with open(config["pcap_file"]) as f:
        pcap = dpkt.pcap.Reader(f)
        filter_packets(pcap, config)


if __name__ == '__main__':
    main()
