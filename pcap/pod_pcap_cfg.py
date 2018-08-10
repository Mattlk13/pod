#!/usr/bin/env python

import json

pack = { 
    "source": "192.168.230.21", 
    "destination": "192.168.230.11",
    "protocol": 17,
    "dst_port": 51234
    }


config = {"pcap_file": "ens1d1_20180619_001.pcap", 
          "pack": pack, 
          "output_file": "ens1d1_20180619_001.output"}

with open('pod.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
