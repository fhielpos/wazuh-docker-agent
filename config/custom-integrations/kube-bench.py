#!/var/ossec/framework/python/bin/python3

import json
import logging
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

socketAddr = '/var/ossec/queue/sockets/queue'

def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:kube-bench:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

finished = False
retries = 0

while not finished or retries == 5:
    try:
        with open('kube-json.json', 'r') as result:
            json_output = json.loads(result.read())
            for scan in json_output['Controls']:
                for test in scan['tests']:
                    for result in test['results']:
                        msg = result
                        msg['node_type'] = scan['node_type']
                        msg['policy'] = scan['text']
                        msg['section_description'] = test['desc']
                        msg['integration'] = 'kube-bench'
            print(json_output['Totals'])
        finished = True
    except FileNotFoundError:
        retries += 1
        if retries != 5:
            logging.warning("kube-bench output file not found. Sleeping 30 seconds.")
            time.sleep(30)
        else:    
            logging.error("kube-bench output not found. Max attempts reached. Exiting")
    except Exception as e:
        logging.error(e)
        break
