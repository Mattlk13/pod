#!/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
import datetime
import socket

def mac_addr(mac_string):
    """Print out MAC address given a string

    Args:
        mac_string: the string representation of a MAC address
    Returns:
        printable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in mac_string)


def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address: the string representation of a MAC address
    Returns:
        printable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)

def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            # print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue

        # Now unpack the data within the Ethernet frame (the IP packet) 
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK


        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        tcp =  ip.data


        # print 'len: ', len(tcp.data)`
        tcp_size = len(tcp.data)
        if tcp_size<100:
            continue

        # Print out the timestamp in UTC
        # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        print 'Timestamp: ', int(timestamp)

        print 'Len: ', len(tcp.data)
        size =  len(buf)

        # for x in buf[size-9:]:
        #     # print hex(ord(x)),
        #     print '%02x' % ord(x),

        # print '\n',

        print ' '.join('%02x' % ord(x) for x in buf[size-9:])

        print ''.join('%02x' % ord(x) for x in buf[size-9:])

        # print 'buf len: ', len(buf)
        # print hex(ord(buf[size-i]))
        # Print out the info
        print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)


        # print hex(ord(tcp.data[tcp_size-1:]))
        # print hex(int(tcp.data[tcp_size-1:],16))
        # print int('20', 16)
        # print 'sport: %d, dport: %d' % (tcp.sport, tcp.dport)

def test():
    """Open up a test pcap file and print out the packets"""
    with open('data/case_0129_1400_z.pcap') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


if __name__ == '__main__':
    test()
