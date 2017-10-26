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
parser.add_option('-v', '--vebose', dest='verbose', action='store_true',
                  help='Verbose mode')
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

def read_watch_devices(file='devices.txt'):
    f = open(file)
    lines = f.readlines()
    f.close

    devices = {}
    for line in lines:
        r = re.compile('([0-9a-f:]+)\s+(\S+)\s+(\S.*)', re.IGNORECASE)
        m = r.search(line)
        if m == None:
            continue
        mac = m.group(1).strip().strip('"')
        watching = (m.group(2).strip().strip('"').lower() == 'true')
        name = m.group(3).strip().strip('"')
        if len(name) == 0:
            name = mac
        devices[mac] = {'name': name, 'watching': watching}
    return devices

def scan_devices(interface, args):
    cmds = ['arp-scan', '-I', options.interface, *args]
    output = subprocess.check_output(cmds).decode('utf-8')
    devices = {}
    for line in output.split('\n'):
        r = re.compile('(\S+)\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})\s+.*', re.IGNORECASE)
        m = r.search(line)
        if m == None:
            continue
        ip = m.group(1).strip()
        mac = m.group(2).strip()
        devices[mac] = ip
    return devices

def need_to_notify(mac):
    if mac in watch_devices:
        return watch_devices[mac]['watching']
    return options.verbose

def record_history(st, now):
    today = now.strftime('%Y-%m-%d')
    if 'history' not in st:
        st['history'] = {}
    if today not in st['history']:
        st['history'][today] = 0
    st['history'][today] += 1
    for d in st['history'].keys():
        if (now - datetime.strptime(d, '%Y-%m-%d')).days > config.getint('app', 'history_days'):
            del st[d]


config = configparser.ConfigParser()
config.read('app.conf')
watch_devices = read_watch_devices()
cur_devices = scan_devices(options.interface, args)
if os.path.exists('state.json'):
    state = json.load(open('state.json'))
else:
    state = {}
state_changed = False
ST_EXIT = 'exit'
ST_ENTER = 'enter'
ST_BEFORE_EXIT = 'before-exit'


for mac, ip in cur_devices.items():
    if mac not in state:
        state[mac] = {'state': ST_EXIT}
        state_changed = True
    st = state[mac]
    st['ip'] = ip
    state_changed = True
    now = datetime.now()
    record_history(st, now)
    if st['state'] == ST_EXIT or st['state'] == ST_BEFORE_EXIT:
        st['state'] = ST_ENTER
        if need_to_notify(mac):
            name = mac if mac not in watch_devices else watch_devices[mac]['name']
            print(json.dumps({
                'value1': 'detecetd',
                'value2': name,
                'value3': now.strftime('%Y-%m-%d %H:%M:%S'),
            }, ensure_ascii=False))
    if st['state'] == ST_ENTER:
        st['last_seen'] = now.timestamp()
        st['last_seen_str'] = now.strftime('%Y-%m-%d %H:%M:%S')

tconf = config.getint('app', 'exit_seconds_after_lost_device')
for mac, st in state.items():
    if mac in cur_devices:
        continue
    if st['state'] == ST_EXIT:
        continue
    if st['state'] == ST_ENTER:
        st['state'] = ST_BEFORE_EXIT
        state_changed = True
    if st['state'] == ST_BEFORE_EXIT:
        now = datetime.now()
        dt = now.timestamp() - st['last_seen']
        if dt >= tconf:
            st['state'] = ST_EXIT
            state_changed = True
            if need_to_notify(mac):
                name = mac if mac not in watch_devices else watch_devices[mac]['name']
                print(json.dumps({
                    'value1': 'lost',
                    'value2': name,
                    'value3': st['last_seen_str'],
                }, ensure_ascii=False))

if state_changed:
    with open('state.json', 'w') as outfile:
        outfile.write(json.dumps(state, ensure_ascii=False))
