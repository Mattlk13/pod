#!/usr/bin/env python

import json

send_pack = { 
    "source": "192.168.230.129", 
    "destination": "192.168.230.137",
    "size": [372]
    }

recv_pack = {
    "source": "192.168.230.137", 
    "destination": "192.168.230.129",
    "size": [170, 200]
    }


config = {"pcap_file": "./xena_20180808_001.pcap", 
          "send": send_pack, 
          "recv":recv_pack, 
          "output_file": "./xena_20180808_001.data"}

with open('pod_fema.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
