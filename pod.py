#!/usr/bin/env python

"""
"""
import dpkt
import datetime
import socket
import json

def read_config():
    with open("pod.cfg") as f:
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

    cur_ts = 0
    in_hw_ts = 0
    in_hw_ts_str = ""
    out_hw_ts = 0
    out_hw_ts_str = ""

    f_output = open(config["output_file"], "w") 

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

        if size!=config["input"]["size"] and size!=config["output"]["size"]:
            continue

        check_sum = buf[size-1]

        if ord(check_sum)!=int(config["timestamp"]["checksum"], 16):
            continue

        hw_ts_size = config["timestamp"]["size"]

        hw_ts_str = ' '.join('%02x' % ord(x) for x in buf[size-hw_ts_size:])
        hw_ts = int(''.join('%02x' % ord(x) for x in buf[size-hw_ts_size:size-1]), 16)

        ip = eth.data
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        is_input = True
        if ip_src == config["input"]["source"] and ip_dst == config["input"]["destination"]:
            in_hw_ts = hw_ts
            in_hw_ts_str = hw_ts_str
            # print "input %s  ==> %d" % (in_hw_ts_str, in_hw_ts)
        elif ip_src == config["output"]["source"] and ip_dst == config["output"]["destination"]:
            out_hw_ts = hw_ts
            out_hw_ts_str = hw_ts_str
            is_input = False
            # print "output %s ==> %d" % (out_hw_ts_str, out_hw_ts)

        if cur_ts!=int(ts):

            if cur_ts!=0:
                print "retransmission: ", cur_ts

            cur_ts = int(ts)

            if is_input:
                out_hw_ts = 0
            else:
                in_hw_ts = 0

        elif in_hw_ts!=0 and out_hw_ts!=0:
            f_output.write("%d\t%s\t%s\t%d\n" % (cur_ts, in_hw_ts_str, out_hw_ts_str, out_hw_ts-in_hw_ts))
            cur_ts = 0
            in_hw_ts = 0
            out_hw_ts = 0

            # in_hw_ts = 0
            # out_hw_ts = 0

        # Print out the ts in UTC
        # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        # print 'Timestamp: ', int(ts)
        # print hw_ts

def main():
    
    config = read_config()

    with open(config["data_file"]) as f:
        pcap = dpkt.pcap.Reader(f)
        filter_packets(pcap, config)


if __name__ == '__main__':
    main()
