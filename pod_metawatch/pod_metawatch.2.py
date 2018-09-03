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

    f_output = open(config["output2_file"], "w") 

    t2_lens = []
    t3_lens = []
    exp_ts = 't2'
    # For each packet in the pcap process the contents
    for _, buf in pcap:

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
        source = buf[size-1]

        ip = eth.data
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        # metamako_ts_str = ' '.join('%02x' % ord(x) for x in buf[size-16:])
        hw_second = int(''.join('%02x' % ord(x) for x in buf[size-12:size-8]), 16)
        hw_ns = int(''.join('%02x' % ord(x) for x in buf[size-8:size-4]), 16)
        
        # if ord(source) == config["t0"]["source"] \
        #     and exp_ts == 't0' \
        #     and size in config["t0"]["size"]:
        #     f_output.write('%d.%09d' % (hw_second, hw_ns))
        #     exp_ts = 't1'
        # elif ord(source) == config["t1"]["source"] \
        #     and exp_ts == 't1':
        #     if size>100 and size not in lens:
        #         lens.append(size)
        #     if size >= config["t1"]["size"][0] \
        #         and size <= config["t1"]["size"][1]:
        #         f_output.write('\t%d.%09d\n' % (hw_second, hw_ns))
        #         exp_ts = 't0'
        if ord(source) == config["t2"]["source"] \
            and exp_ts == 't2' \
            and ip_src == config["t2"]["src_ip"] \
            and ip_dst == config["t2"]["dest_ip"]:
            
            if size>100 and size not in t2_lens:
                t2_lens.append(size)
            
            if size in config["t2"]["size"]:
                # and size <= config["t2"]["size"][1]:
                f_output.write('%d.%09d' % (hw_second, hw_ns))
                exp_ts = 't3'
        elif ord(source) == config["t3"]["source"] \
            and exp_ts == 't3' \
            and ip_src == config["t3"]["src_ip"] \
            and ip_dst == config["t3"]["dest_ip"]:
            
            if size>100 and size not in t3_lens:
                t3_lens.append(size)
            
            if size in config["t3"]["size"]:
                # and size <= config["t3"]["size"][1]:
                f_output.write('\t%d.%09d\n' % (hw_second, hw_ns))
                exp_ts = 't2'
        else:
            continue
        

        # Print out the ts in UTC
        # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        # print 'Timestamp: ', int(ts)
        # print hw_ts
    
    # f_output.write('\n')

    print(t2_lens)
    print(t3_lens)

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
