#!/usr/bin/env python

import json

t0_pack = { 
    "source": 11, 
    "src_ip": "192.168.230.129",
    "dst_ip": "192.168.230.139",
    "dst_port": 8002,
    "size": [400]
    }

t1_pack = {
    "source": 16, 
    "src_ip": "192.168.230.243",
    "dst_ip": "220.248.39.174",
    "dst_port": 33005,
    "size": [285, 297]
    }

t2_pack = { 
    "source": 15, 
    "src_ip": "220.248.39.174",
    "dst_ip": "192.168.230.243",
    "src_port": 33005,
    "size": [192, 203]
    }

t3_pack = {
    "source": 12, 
    "src_ip": "192.168.230.139",
    "dst_ip": "192.168.230.129",
    "src_port": 8002,
    "size": [242, 253]
    }

config = {"pcap_file": "./metawatch_ciara_20180903_002.pcap", 
          "t0": t0_pack,
          "t1": t1_pack, 
          "t2": t2_pack, 
          "t3": t3_pack,
          "output_file": "./metawatch_ciara_20180903_002.data"}

with open('ciara_metawatch.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
