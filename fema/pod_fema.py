#!/usr/bin/env python

"""
"""
import dpkt
import datetime
import socket
import json
import argparse
import os
import math

def sort(data_file):
    cmd_sort = 'sort -k 2n,2n -k 3,3  -k 4n,4n %s > %s.sort' % (data_file, data_file)
    os.system(cmd_sort)

def merge(data_file):
    f_output = open('%s.merge' % data_file, "w")

    pre_order = -1
    cur_order = -1
    exp_ts_flag = 0
    no_list = []
    ts_list = []
    with open('%s.sort' % data_file) as f:
        for line in f:
            fields = line.split()
            no = int(fields[0])
            order = int(fields[1])
            ts_flag = int(fields[2][1])
            ts = fields[3]
            
            if cur_order != order:
                pre_order = cur_order
                cur_order = order
            
                if len(ts_list) ==0 or len(ts_list) == 2:
                    pass
                else:
                    print("Error: order %d" % pre_order)
                    # exit()
                    ts_list = []
                    no_list = []
                    exp_ts_flag = ts_flag

            if exp_ts_flag % 2 == ts_flag:
                ts_list.append(ts)
                no_list.append(no)
                
                exp_ts_flag = ts_flag + 1

                if ts_flag == 1:
                    f_output.write('%d' % cur_order)
                    for no in no_list:
                        f_output.write('\t%d' % no)
                    f_output.write('\t')
                    f_output.write('\t'.join(ts_list))
                    f_output.write('\n')
                    ts_list = []
                    no_list = []
            # if exp_ts_flag == ts_flag:
            #     f_output.write('%s' % ts)
        f.close

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
    no = 0
    for _, buf in pcap:
        no = no +1

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
        
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        ip_hdr_len = ip.hl * 4
        ip_len = ip.len

        tcp = ip.data
        # port_src = tcp.sport
        port_dst = tcp.dport
        tcp_hdr_len = tcp.off * 4
        tcp_payload_len = ip_len - ip_hdr_len - tcp_hdr_len
        paylod_position = 14 + ip_hdr_len + tcp_hdr_len
        
        # print('ip_hdr_len %d, ip_len %d' % (ip_hdr_len, ip_len))
        # print('tcp_hdr_len %d, tcp_payload_len %d' % (tcp_hdr_len, tcp_payload_len))
        # print('no %d' % no)
        # exit(-1)
        
        if config["ts_format"] == "metawatch":
            source = buf[size-1]
            
            # metamako_ts_str = ' '.join('%02x' % ord(x) for x in buf[size-16:])
            hw_second = int(''.join('%02x' % ord(x) for x in buf[size-12:size-8]), 16)
            hw_ns = int(''.join('%02x' % ord(x) for x in buf[size-8:size-4]), 16)
        elif config["ts_format"] == "hpt":
            # hpt_ts_str = ' '.join('%02x' % ord(x) for x in buf[size-10:size-1])
            # print ('hpt_ts_str:%s' % hpt_ts_str)
            source = buf[size-11]
            
            hw_second = int(''.join('%02x' % ord(x) for x in buf[size-10:size-6]), 16)
            hw_ns = int(''.join('%02x' % ord(x) for x in buf[size-6:size-1]), 16)
            # print('before: hw_ns %d' % hw_ns)
            hw_ns = int(hw_ns * 2**-40 * 10**9)
            # print('after: hw_ns %d' % hw_ns)
            # break
        else:
            print("The ts_format %s is not be supported." % config["ts_format"])
            break
        
        # ord(source) == config["t0"]["source"]
        if  ip_src == config["t0"]["src_ip"] \
            and ip_dst == config["t0"]["dst_ip"] \
            and port_dst == config["t0"]["dst_port"] \
            and size >= config["t0"]["size"]:
            
            ts = 't0'

            # print(' '.join('%02x' % ord(x) for x in buf[68:70]))
            pkg_size = int(''.join('%02x' % ord(x) for x in buf[68:70]), 16)
            # print('pkg_size %d' % pkg_size)

            if pkg_size != 314:
                continue

            position = size - 181
            # 195 = 318 + 4 + 54 - 181
            while position >= 195:
                order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[position:position+20]), 10)
                f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, order_local_id, ts, hw_second, hw_ns))
                position = position - 318
        
            # print("No %d - t0 order_local_id = %d" % (no,order_local_id))
            # print("%d => %d" % (port_src, port_dst))
            # ord(source) == config["t1"]["source"]
        elif ip_src == config["t1"]["src_ip"] \
            and ip_dst == config["t1"]["dst_ip"] \
            and port_dst == config["t1"]["dst_port"] \
            and size >= config["t1"]["size"]:
            # f_output.write('\t%d.%09d\n' % (hw_second, hw_ns))
            
            ts = 't1'
            # paylod_position += 2
            pkg_size = int(''.join('%02x' % ord(x) for x in buf[paylod_position + 2 : paylod_position + 4]), 16)
            # if size == 297:
            #     pkg_size = int(''.join('%02x' % ord(x) for x in buf[80:82]), 16)
            # else:
            #     pkg_size = int(''.join('%02x' % ord(x) for x in buf[68:70]), 16)
            
            # print('paylod_position %d' % paylod_position)
            # print('pkg_size %d' % pkg_size)
            # exit(-1)
            
            if pkg_size != 199 and pkg_size != 236:
                continue
            
            # paylod_position += 161
            # position = size - 59
            # 202 = 203 + 4 + 54 - 59
            while paylod_position + 160 < ip_len:
                order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[paylod_position + 160:paylod_position + 160 +13]), 10)
                order_local_id = order_local_id - config["t1"]["order_delta"]
                f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, order_local_id, ts, hw_second, hw_ns))
                paylod_position += pkg_size + 4
            # if size == 488:
            #     pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-262:size-249]), 10)
            #     f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
            # order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-59:size-46]), 10)

            
            # print("No %d - t1 order_local_id = %d" % (no, order_local_id))
        # elif ord(source) == config["t2"]["source"] \
        #     and ip_src == config["t2"]["src_ip"] \
        #     and ip_dst == config["t2"]["dst_ip"] \
        #     and port_src == config["t2"]["src_port"] \
        #     and size in config["t2"]["size"]:
    
        #     ts = 't2'
        #     if size == 320:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-153:size-140]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))

        #     if size == 324:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-155:size-142]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
        #     if size == 328 or size == 451 \
        #         or size == 574:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-157:size-144]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
        #     if size == 330:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-159:size-146]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
        #     if size == 451 or size == 574:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-280:size-267]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
        #     if size == 574:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-403:size-390]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
        #     order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-34:size-21]), 10)
            
        #     # if size == 328:
        #     #     print('size is 328, no is %d' % no)
        #     # elif size == 194:
        #     #     order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-32:size-19]), 10)
            
        #     # print("No %d - t2 order_local_id = %d" % (no, order_local_id))
        # elif ord(source) == config["t3"]["source"] \
        #     and ip_src == config["t3"]["src_ip"] \
        #     and ip_dst == config["t3"]["dst_ip"] \
        #     and port_src == config["t3"]["src_port"] \
        #     and size in config["t3"]["size"]:
        #     # f_output.write('\t%d.%09d\n' % (hw_second, hw_ns))
        #     ts = 't3'

        #     if size == 418:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-295:size-275]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))

        #     if size == 420:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-296:size-276]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))
            
        #     if size == 426:
        #         pre_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-299:size-279]), 10)
        #         f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, pre_local_id, ts, hw_second, hw_ns))

        #     if size == 139 or size == 242:
        #         order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-116:size-96]), 10)
        #     elif size == 249 or size == 250 \
        #         or size == 251 \
        #         or size == 252 or size == 253 \
        #         or size == 254 \
        #         or size == 418 or size == 420 \
        #         or size == 426:
        #         order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[size-127:size-107]), 10)
            
            # print("No %d - t3 order_local_id = %d" % (no, order_local_id))
        else:
            continue
        
        # f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, order_local_id, ts, hw_second, hw_ns))
        

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

    sort(config['output_file'])

    merge(config['output_file'])

if __name__ == '__main__':
    main()
