#!/usr/bin/env python

"""
"""
import dpkt
import argparse
import json
import sys

def filter_packets(pcap):

    # For each packet in the pcap process the contents
    no = 0
    for _, buf in pcap:
        dict_ts_trailer = {}
        
        no = no +1
        dict_ts_trailer["no"] = no
        
        size = len(buf)

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        # eth = dpkt.ethernet.Ethernet(buf)
        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        # if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        #     continue
        
        # ip = eth.data
        # if ip.p != dpkt.ip.IP_PROTO_TCP:
        #     continue
        
        # tcp = ip.data
        # port_src = tcp.sport
        # port_dst = tcp.dport

        dict_metamako_ts_trailer = {}
        metawatch_ts_trailer = buf[size-16:]
        ts_hex_dump = ' '.join('%02x' % ord(x) for x in metawatch_ts_trailer)
        dict_metamako_ts_trailer["hex"] = ts_hex_dump
        # print('no %d, metawatch_ts_trailer: \n %s' % (no, ts_hex_dump))

        original_fcs = ' '.join('%02x' % ord(x) for x in metawatch_ts_trailer[0:4])
        # print('original_fcs: %s' % original_fcs)
        dict_metamako_ts_trailer["original_fcs"] = original_fcs

        seconds_since_epoch_hex_dump = ' '.join('%02x' % ord(x) for x in metawatch_ts_trailer[4:8])
        seconds_since_epoch = int(''.join('%02x' % ord(x) for x in metawatch_ts_trailer[4:8]), 16)
        # print('seconds_since_epoch  %d <==> %s' % (seconds_since_epoch, seconds_since_epoch_hex_dump))
        dict_seconds_since_epoch = {}
        dict_seconds_since_epoch["hex"] = seconds_since_epoch_hex_dump
        dict_seconds_since_epoch["dec"] = seconds_since_epoch
        dict_metamako_ts_trailer["seconds_since_epoch"] = dict_seconds_since_epoch

        nanoseconds_hex_dump = ' '.join('%02x' % ord(x) for x in metawatch_ts_trailer[8:12])
        nanoseconds = int(''.join('%02x' % ord(x) for x in metawatch_ts_trailer[8:12]), 16)
        # print('nanoseconds %d <==> %s' % (nanoseconds, nanoseconds_hex_dump))
        dict_nanoseconds = {}
        dict_nanoseconds["dec"] = nanoseconds
        dict_nanoseconds["hex"] = nanoseconds_hex_dump
        dict_metamako_ts_trailer["nanoseconds"] = dict_nanoseconds

        flags = metawatch_ts_trailer[12]
        # print('flags: %d <==> %02x' % (ord(flags), ord(flags)))
        dict_metamako_ts_trailer["flags"] = ord(flags)

        device_id_hex_dump = ' '.join('%02x' % ord(x) for x in metawatch_ts_trailer[13:15])
        device_id = int(''.join('%02x' % ord(x) for x in metawatch_ts_trailer[13:15]), 16)
        # print('device_id: %d <==> %s' % (device_id, device_id_hex_dump))
        dict_device_id = {}
        dict_device_id["dec"] = device_id
        dict_device_id["hex"] = device_id_hex_dump
        dict_metamako_ts_trailer["device_id"] = dict_device_id

        port = metawatch_ts_trailer[15]
        # print('port: %d <==> %02x' % (ord(port), ord(port)))
        dict_metamako_ts_trailer["port"] = ord(port)

        dict_ts_trailer["metamako_ts_trailer"] = dict_metamako_ts_trailer

        json.dump(dict_ts_trailer, sys.stdout, sort_keys=True, indent=4)
        print('')
        
        # break

        
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
