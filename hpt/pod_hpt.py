#!/usr/bin/env python

"""
"""
import dpkt
import argparse

def filter_packets(pcap):

    # For each packet in the pcap process the contents
    no = 0
    for _, buf in pcap:
        no = no +1

        size = len(buf)

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        
        # ip = eth.data
        # if ip.p != dpkt.ip.IP_PROTO_TCP:
        #     continue
        
        # tcp = ip.data
        # port_src = tcp.sport
        # port_dst = tcp.dport

        exablaze_ts_trailer = buf[size-16:]
        ts_hex_dump = ' '.join('%02x' % ord(x) for x in exablaze_ts_trailer)
        print('no %d, exablaze_ts_trailer: \n %s' % (no, ts_hex_dump))

        original_fcs = ' '.join('%02x' % ord(x) for x in exablaze_ts_trailer[0:4])
        print('original_fcs: %s' % original_fcs)

        device_id = exablaze_ts_trailer[4]
        print('device_id: %d <==> %02x' % (ord(device_id), ord(device_id)))

        port = exablaze_ts_trailer[5]
        print('port: %d <==> %02x' % (ord(port), ord(port)))

        seconds_since_epoch_hex_dump = ' '.join('%02x' % ord(x) for x in exablaze_ts_trailer[6:10])
        seconds_since_epoch = int(''.join('%02x' % ord(x) for x in exablaze_ts_trailer[6:10]), 16)
        print('seconds_since_epoch  %d <==> %s' % (seconds_since_epoch, seconds_since_epoch_hex_dump))

        frac_seconds_hex_dump = ' '.join('%02x' % ord(x) for x in exablaze_ts_trailer[10:15])
        frac_seconds = int(''.join('%02x' % ord(x) for x in exablaze_ts_trailer[10:15]), 16)
        frac_nano_seconds = frac_seconds * 2**-40 * 10**9
        print('frac_seconds %d <==> %s ==> %09d(ns)' % (frac_seconds, frac_seconds_hex_dump, frac_nano_seconds))

        _reserved = exablaze_ts_trailer[15]
        print('_reserved: %02x' % ord(_reserved))
        
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="pcap file")
    args = parser.parse_args()

    pcap_file = args.file

    with open(pcap_file) as f:
        pcap = dpkt.pcap.Reader(f)
        filter_packets(pcap)

if __name__ == '__main__':
    main()
