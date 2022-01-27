#!/usr/bin/env python

import json
import time
from socket import socket, AF_UNIX, SOCK_DGRAM


socketAddr = '/var/ossec/queue/sockets/queue'

def send_event(msg):
    try:
        print('Sending {} to {} socket.'.format(msg, socketAddr))
        string = '1:kube-bench:{}'.format(msg)
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socketAddr)
        sock.send(string.encode())
        sock.close()
        print("Message sent")
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
                print("Scan:", scan['text'])
                for test in scan['tests']:
                    for result in test['results']:
                        print("Check:", result['test_number'])
                        print("Check status:", result['status'], result['test_desc'])
                        result['node_type'] = scan['node_type']
                        result['policy'] = scan['text']
                        result['section_description'] = test['desc']
                        msg = {}
                        msg['integration'] = 'kube-bench'
                        msg['kube_bench'] = result
                        send_event(json.dumps(msg))
        finished = True
    except:
        retries += 1
        if retries != 5:
            print("kube-bench output file not found. Sleeping 30 seconds.")
            time.sleep(30)
        else:    
            print("kube-bench output not found. Max attempts reached. Exiting")