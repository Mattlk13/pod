#!/usr/bin/env python

import json

input_pack = { 
    "source": "172.31.0.4", 
    "destination": "172.31.0.5",
    "size": 171
    }

output_pack = {
    "source": "10.47.109.59", 
    "destination": "192.168.11.131",
    "size": 278
    }

timestamp = {
    "size": 9,
    "checksum": "0xc3"
    }

config = {"data_file": "data/case_0217_1440_s.pcap", 
          "input": input_pack, 
          "output":output_pack, 
          "timestamp": timestamp, 
          "output_file": "data/up_delay_s_0217_1440.data"}

with open('pod.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
