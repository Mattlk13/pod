#!/usr/bin/env python

import json

ftd_pack = {
    "src_ip": "192.168.230.198",
    "dst_ip": "124.74.244.174",
    "dst_port": 33005
    }


# ts_format : hpt or metawatch
config = {"pcap_file": "./exa_hpt_hp_x1_20181029_001.pcap", 
          "ftd": ftd_pack,
          "output_file": "./exa_hpt_hp_x1_20181029_001.data"}

with open('ftd.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
