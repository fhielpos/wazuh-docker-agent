#!/usr/bin/env python

import json
import logging
import time
import sys
from socket import socket, AF_UNIX, SOCK_DGRAM

logging.basicConfig(stream=sys.stdout)

socketAddr = '/var/ossec/queue/sockets/queue'

def send_event(msg):
    try:
        logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
        string = '1:kube-bench:{}'.format(msg)
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socketAddr)
        sock.send(string.encode())
        sock.close()
    except:
        logging.exception("Error sending message to Wazuh socket.")

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
    except:
        retries += 1
        if retries != 5:
            logging.warning("kube-bench output file not found. Sleeping 30 seconds.")
            time.sleep(30)
        else:    
            logging.error("kube-bench output not found. Max attempts reached. Exiting")