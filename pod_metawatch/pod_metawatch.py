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
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        tcp = ip.data
        port_src = tcp.sport
        port_dst = tcp.dport

        

        # metamako_ts_str = ' '.join('%02x' % ord(x) for x in buf[size-16:])
        hw_second = int(''.join('%02x' % ord(x) for x in buf[size-12:size-8]), 16)
        hw_ns = int(''.join('%02x' % ord(x) for x in buf[size-8:size-4]), 16)
        
        if ord(source) == config["t0"]["source"] \
            and ip_src == config["t0"]["src_ip"] \
            and ip_dst == config["t0"]["dst_ip"] \
            and port_dst == config["t0"]["dst_port"] \
            and size in config["t0"]["size"]:
            f_output.write('%d.%09d' % (hw_second, hw_ns))

            order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-181:size-161]), 10)
            print("t0 order_local_id = %d" % order_local_id)
            # print("%d => %d" % (port_src, port_dst))
        elif ord(source) == config["t1"]["source"] \
            and ip_src == config["t1"]["src_ip"] \
            and ip_dst == config["t1"]["dst_ip"] \
            and port_dst == config["t1"]["dst_port"] \
            and size in config["t1"]["size"]:
            f_output.write('\t%d.%09d' % (hw_second, hw_ns))
            
            order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-59:size-46]), 10)
            print("t1 order_local_id = %d" % order_local_id)
        elif ord(source) == config["t2"]["source"] \
            and ip_src == config["t2"]["src_ip"] \
            and ip_dst == config["t2"]["dst_ip"] \
            and port_src == config["t2"]["src_port"] \
            and size in config["t2"]["size"]:
            f_output.write('\t%d.%09d' % (hw_second, hw_ns))
    
            order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-34:size-21]), 10)
            print("t2 order_local_id = %d" % order_local_id)
        elif ord(source) == config["t3"]["source"] \
            and ip_src == config["t3"]["src_ip"] \
            and ip_dst == config["t3"]["dst_ip"] \
            and port_src == config["t3"]["src_port"] \
            and size in config["t3"]["size"]:
            f_output.write('\t%d.%09d\n' % (hw_second, hw_ns))
            if size == 242:
                order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-116:size-96]), 10)
            elif size == 253:
                order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-127:size-107]), 10)
            
            print("t3 order_local_id = %d" % order_local_id)
        else:
            continue
        

        # Print out the ts in UTC
        # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        # print 'Timestamp: ', int(ts)
        # print hw_ts
    
    # f_output.write('\n')

    # print(lens)

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
