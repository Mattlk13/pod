#!/usr/bin/env python

import json

input_pkg = { 
    "source": "172.31.0.4", 
    "destination": "172.31.0.1",
    "size": 269
    }

output_pkg = {
    "source": "10.47.109.56", 
    "destination": "192.168.11.131",
    "size": 269
    }

timestamp = {
    "size": 9,
    "checksum": "0xc3"
    }

config = {"input": input_pkg, "output":output_pkg, "timestamp": timestamp}

with open('pod.cfg', 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
