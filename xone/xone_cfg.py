#!/usr/bin/env python

import json

t0_pack = { 
    "source": 1, 
    "src_ip": "192.168.230.129",
    "dst_ip": "192.168.230.137",
    "dst_port": 50001,
    "size": 187
    }

t1_pack = {
    "source": 4, 
    "src_ip": "192.168.230.198",
    "dst_ip": "124.74.244.174",
    "dst_port": 33005,
    "size": 285,
    "order_delta": 0
    }

# t2_pack = { 
#     "source": 15, 
#     "src_ip": "124.74.244.174",
#     "dst_ip": "192.168.230.194",
#     "src_port": 33005,
#     "size": [192, 194, 203, 205, 320, 324, 328, 330, 451, 574]
#     }

# t3_pack = {
#     "source": 12, 
#     "src_ip": "192.168.230.147",
#     "dst_ip": "192.168.230.129",
#     "src_port": 8002,
#     "size": [239, 242, 249, 250, 251, 252, 253, 254, 418, 420, 426]
#     }

# ts_format : hpt or metawatch
config = {"pcap_file": "./exa_hpt_hp_x1_20181030_001.pcap", 
          "t0": t0_pack,
          "t1": t1_pack, 
        #   "t2": t2_pack, 
        #   "t3": t3_pack,
          "ts_format": "hpt",
          "output_file": "./exa_hpt_hp_x1_20181030_001.data"}

with open('hp_xone_hpt.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
