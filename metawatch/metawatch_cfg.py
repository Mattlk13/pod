#!/usr/bin/env python

import json

t0_pack = { 
    "source": 11, 
    "src_ip": "192.168.230.129",
    "dst_ip": "192.168.230.147",
    "dst_port": 8002,
    "size": 400
    }

t1_pack = {
    "source": 16, 
    "src_ip": "192.168.230.194",
    "dst_ip": "124.74.244.174",
    "dst_port": 33005,
    "size": 285,
    "order_delta": 0
    }

t2_pack = { 
    "source": 15, 
    "src_ip": "124.74.244.174",
    "dst_ip": "192.168.230.194",
    "src_port": 33005,
    "size": [192, 194, 203, 205, 320, 324, 328, 330, 451, 574]
    }

t3_pack = {
    "source": 12, 
    "src_ip": "192.168.230.147",
    "dst_ip": "192.168.230.129",
    "src_port": 8002,
    "size": [239, 242, 249, 250, 251, 252, 253, 254, 418, 420, 426]
    }

config = {"pcap_file": "./metawatch_dell_onload_20180920_001.pcap", 
          "t0": t0_pack,
          "t1": t1_pack, 
          "t2": t2_pack, 
          "t3": t3_pack,
          "output_file": "./metawatch_dell_onload_20180920_001.data"}

with open('dell_metawatch.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
