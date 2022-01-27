#!/usr/bin/env python

import json
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

socketAddr = '/var/ossec/queue/sockets/queue'

def send_event(msg):
    try:
        #print('Sending {} to {} socket.'.format(msg, socketAddr))
        string = '1:kube-bench:{}'.format(msg)
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.sendto(string.encode(), socketAddr)
    except:
        print("Error sending message to Wazuh socket.")

finished = False
retries = 0

time.sleep(10)

while not finished and retries != 5:
    try:
        with open('/var/log/kube-bench/kube-bench.json', 'r') as result:
            json_output = json.loads(result.read())
            for scan in json_output['Controls']:
                for test in scan['tests']:
                    for result in test['results']:
                        result['node_type'] = scan['node_type']
                        result['policy'] = scan['text']
                        result['section_description'] = test['desc']
                        msg = {}
                        msg['integration'] = 'kube-bench'
                        msg['kube_bench'] = result
                        send_event(json.dumps(msg))
        finished = True
        
        # Give time to Wazuh to send the messages before killing it
        time.sleep(60)
    except:
        retries += 1
        if retries != 5:
            print("kube-bench output file not found. Sleeping 30 seconds.")
            time.sleep(30)
        else:    
            print("kube-bench output not found. Max attempts reached. Exiting")