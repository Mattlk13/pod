#!/usr/bin/env python

"""
"""
import dpkt
import socket
import argparse
import json
import sys

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

    # For each packet in the pcap process the contents
    no = 0
    
    for _, buf in pcap:
        no = no +1
        
        # size = len(buf)

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        
        ip = eth.data
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        # port_src = tcp.sport
        port_dst = tcp.dport

        if ip_src == config["ftd"]["src_ip"] \
            and ip_dst == config["ftd"]["dst_ip"] \
            and port_dst == config["ftd"]["dst_port"]:

            payload = tcp.data
            print('tcp payload:\n%s' % ' '.join('%02x' % ord(x) for x in payload))

            list_ftds = []
            index = 0
            while index <len(payload):
                # ftd head
                ftd_head_hex_dump = ' '.join('%02x' % ord(x) for x in payload[index : index + 4])
                ftd_type = ord(payload[index])
                index += 1
                
                extension_length = ord(payload[index])
                index += 1
                
                content_length = int(''.join('%02x' % ord(x) for x in payload[index : index + 2]), 16)
                index += 2
                
                dict_ftd_head = {
                    "hex": ftd_head_hex_dump,
                    "type": ftd_type,
                    "extension_length": extension_length,
                    "content_length": content_length
                }

                # ftd_extension_head
                dict_ftd_extension_head = {}
                if extension_length > 0:
                    extension_head_hex_dump = ' '.join('%02x' % ord(x) for x in payload[index : index + extension_length])
                    index += extension_length

                    dict_ftd_head_extension["hex"] = extension_head_hex_dump

                dict_ftdc = {}
                if content_length > 0:
                    ftdc = payload[index : index + content_length]
                    ftdc_hex_dump = ' '.join('%02x' % ord(x) for x in ftdc)
                    index += content_length
                    dict_ftdc["hex"] = ftdc_hex_dump

                    # compressor LZ77
                    # uncompress_ftdc = LZ77(6).compress(list(ftdc))
                    # uncompress_ftdc_hex_dump = ' '.join('%02x' % ord(x) for x in uncompress_ftdc)
                    # dict_ftdc["uncom_hex"] = uncompress_ftdc_hex_dump

                    # ftdc_head
                    # ftdc_head = ftdc[0:16]
                    # ftdc_head_hex_dump = ' '.join('%02x' % ord(x) for x in ftdc_head)

                    # version = ord(ftdc_head[0])
                    # trasaction_id = int(''.join('%02x' % ord(x) for x in ftdc_head[1:5]), 16)
                    # chain = ord(ftdc_head[5])
                    # sequence_series = int(''.join('%02x' % ord(x) for x in ftdc_head[6:8]), 16)
                    # sequence_number = int(''.join('%02x' % ord(x) for x in ftdc_head[8:12]), 16)
                    # field_count = int(''.join('%02x' % ord(x) for x in ftdc_head[12:14]), 16)
                    # ftdc_content_length = int(''.join('%02x' % ord(x) for x in ftdc_head[14:16]), 16)

                    # dict_ftdc_head = {
                    #     "hex": ftdc_head_hex_dump,
                    #     "version": version,
                    #     "trasaction_id": trasaction_id,
                    #     "chain": chain,
                    #     "sequence_series": sequence_series,
                    #     "sequence_number": sequence_number,
                    #     "field_count": field_count,
                    #     "ftdc_content_length": ftdc_content_length
                    # }

                    # dict_ftdc["head"] = dict_ftdc_head
                    # dict_ftdc["fields"] = []
                    
                    # i_ftdc = 16
                    # while i_ftdc < len(ftdc):
                    #     field_id = int(''.join('%02x' % ord(x) for x in ftdc[i_ftdc:i_ftdc + 4]), 16)
                    #     i_ftdc += 4

                    #     field_length = int(''.join('%02x' % ord(x) for x in ftdc[i_ftdc:i_ftdc + 2]), 16)
                    #     i_ftdc += 2

                    #     field_data = ' '.join('%02x' % ord(x) for x in ftdc[i_ftdc:i_ftdc + field_length])
                    #     i_ftdc += field_length

                    #     dict_field = {
                    #         "id": field_id,
                    #         "length": field_length,
                    #         "data": field_data
                    #     }

                    #     dict_ftdc["fields"].append({"field": dict_field})
                
                dict_ftd = {
                    "head": dict_ftd_head,
                    "extension_head": dict_ftd_extension_head,
                    "ftdc": dict_ftdc
                }

                # ftd_content
                # ftdc_head

                list_ftds.append({"ftd": dict_ftd})

                # break

            dict_pkg = {
                "no": no,
                "ftds": list_ftds
            }
            json.dump(dict_pkg, sys.stdout, sort_keys=True, indent=4)
            print('')

            break
            
            # if size == 297:
            #     pkg_size = int(''.join('%02x' % ord(x) for x in buf[80:82]), 16)
            # else:
            #     pkg_size = int(''.join('%02x' % ord(x) for x in buf[68:70]), 16)
            
            # if pkg_size != 199:
            #     continue
            
            # position = size - 59
            # # 202 = 203 + 4 + 54 - 59
            # while position >= 202:
            #     order_local_id = int(''.join('%s' % chr(ord(x)) for x in buf[position:position+13]), 10)
            #     order_local_id = order_local_id - config["t1"]["order_delta"]
            #     f_output.write('%d\t%d\t%s\t%d.%09d\n' % (no, order_local_id, ts, hw_second, hw_ns))
            #     position = position - 203
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

        
        

        
        
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="config file")
    args = parser.parse_args()

    config = read_config(args.config)

    with open(config["pcap_file"]) as f:
        pcap = dpkt.pcap.Reader(f)
        filter_packets(pcap, config)

if __name__ == '__main__':
    main()
