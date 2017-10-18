# -*- coding: utf-8 -*-
import configparser
import re
import json
import subprocess
from optparse import OptionParser, OptionGroup
import sys
import os
from datetime import datetime, timedelta

import pprint
pp = pprint.PrettyPrinter()

prog = os.path.basename(sys.argv[0])
usage = 'usage: %prog [options] IP-ADDRESS-RANGES...'
parser = OptionParser(usage, add_help_option=False)
parser.add_option("-i", "--interface", dest="interface",
                  help="Use network interface")
parser.add_option('-h', '--help', dest='help', action='store_true',
                  help='show this help message and exit')
(options, args) = parser.parse_args()

if options.help:
    parser.print_help()
    print()
    print('Examples:')
    print('  %s -i eth0 192.168.100.0/24' % prog)
    print('  %s -i eth0 192.168.100.10-200' % prog)
    print('  %s -i eth0 192.168.100.2 192.168.100.3' % prog)
    sys.exit(1)

def read_devices(file='devices.txt'):
    f = open(file)
    lines = f.readlines()
    f.close

    devices = {}
    for line in lines:
        r = re.compile('([0-9a-f:]+)\s+(\S.*)', re.IGNORECASE)
        m = r.search(line)
        if m == None:
            continue
        mac = m.group(1)
        name = m.group(2).strip()
        if name[0] == '"' and name[-1] == '"':
            name = name[1:-1]
        if len(name) == 0:
            name = mac
        devices[mac] = name
    return devices

def scan_devices(interface, args):
    cmds = ['arp-scan', '-I', options.interface, *args]
    output = subprocess.check_output(cmds).decode('utf-8')
    devices = {}
    for line in output.split('\n'):
        r = re.compile('(\S+)\s+([0-9a-f:]+)\s+.*', re.IGNORECASE)
        m = r.search(line)
        if m == None:
            continue
        ip = m.group(1)
        mac = m.group(2)
        devices[mac] = ip
    return devices


config = configparser.ConfigParser()
config.read('app.conf')
watch_devices = read_devices()
cur_devices = scan_devices(options.interface, args)
if os.path.exists('state.json'):
    state = json.load(open('state.json'))
else:
    state = {}
state_changed = False
ST_EXIT = 'exit'
ST_ENTER = 'enter'

for mac, name in watch_devices.items():
    tconf = config.getint('app', 'exit_seconds_after_lost_device')
    if mac not in state:
        state[mac] = {'state': ST_EXIT, 'name': name}
    st = state[mac]
    now = datetime.now()
    #pp.pprint(cur_devices)
    if st['state'] == ST_EXIT:
        if mac in cur_devices:
            st['state'] = ST_ENTER
            st['last_seen'] = now.timestamp()
            st['last_seen_str'] = now.strftime('%Y-%m-%d %H:%M:%S')
            state_changed = True
            print(json.dumps({
                'value1': 'detecetd',
                'value2': name,
                'value3': now.strftime('%Y-%m-%d %H:%M:%S'),
            }, ensure_ascii=False))
    elif st['state'] == ST_ENTER:
        if mac in cur_devices:
            st['last_seen'] = now.timestamp()
            st['last_seen_str'] = now.strftime('%Y-%m-%d %H:%M:%S')
            state_changed = True
        else:
            dt = now.timestamp() - st['last_seen']
            if dt >= tconf:
                st['state'] = ST_EXIT
                state_changed = True
                print(json.dumps({
                    'value1': 'lost',
                    'value2': name,
                    'value3': st['last_seen_str'],
                }, ensure_ascii=False))

if state_changed:
    with open('state.json', 'w') as outfile:
        outfile.write(json.dumps(state, ensure_ascii=False))
