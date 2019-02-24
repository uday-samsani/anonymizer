#!/bin/python3
import sys
import os
import subprocess
import argparse
import re
import random

macRegExp = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})')


def macaddr(s, pat=macRegExp):
    if not pat.match(s):
        print('''MAC address should be in format
                 XX:XX:XX:XX:XX:XX [0-9 a-f A-F]''')
        raise argparse.ArgumentTypeError
    return s


def main():
    # Command-Line argument parser
    parser = argparse.ArgumentParser(description='''Anonymize networ interfaces by
                spoofing hostnames and physical address( MAC address)''')
    network = parser.add_argument_group('MAC Address', '''Give MAC address of
     your choice or make a random MAC address''')
    network.add_argument('-r', '--random', action='store_true')
    network.add_argument('-m', '--mac', type=macaddr, metavar='',
                         help='Physical address (MAC address) to spoof.')
    parser.add_argument('-I', '--iface', type=str, metavar='', required=True,
                        help='Interface to anonymize')
    opt = parser.add_mutually_exclusive_group()
    opt.add_argument('-q', '--quiet', action='store_true')
    opt.add_argument('-v', '--verboose', action='store_true')
    args = parser.parse_args()

    if not (args.mac or args.random):
        parser.error('No MAC address given, add -r or -m')

    # Checking weather the interface given is connected or not
    proc = subprocess.run(['ip', 'link', 'show'], stdout=subprocess.PIPE)
    output = proc.stdout.decode('utf-8')
    output = output.split('\n')
    ifaceList = []
    for i in output:
        temp = i.split(' ')
        if(len(temp) > 1):
            if(temp[1] != ''):
                ifaceList.append(temp[1][0:-1])
    if(args.iface in ifaceList):
        if(args.verboose):
            print("Anonymizing the interface {0}".format(args.iface))
        proc = subprocess.run(['./genhost','1'], stdout=subprocess.PIPE)
        hostname = proc.stdout.decode('utf-8')[:-1]
        subprocess.run(['hostnamectl','set-hostname',"'"+hostname+"'"])
        if(args.verboose):
            print('Hostname changed to {0}'.format(hostname))
        subprocess.run(['service', 'network-manager', 'restart'])
        if(args.verboose):
            print('Network Manager restarted')
        subprocess.run(['ip', 'link', 'set', args.iface, 'down'])
        if(args.verboose):
            print('Interface {0} is down'.format(args.iface))
        if(not args.random):
            subprocess.run(['ip', 'link', 'set', args.iface, 'address',
                            args.mac])
            if(args.quiet):
                print('{1}'.format(args.mac))
            else:
                print('Physical address of interface {0} is spoofed to {1}'.format(args.iface, args.mac))
        else:
            while(True):
                temp = range(6)
                mac = ':'.join('%02x' % random.randint(0, 255) for x in temp)
                proc = subprocess.run(['ip', 'link', 'set', args.iface,
                                       'address', mac], stdout=subprocess.PIPE)
                if(proc.returncode == 0):
                    break
                else:
                    print('{0} Addressfailed')
            if(args.quiet):
                print('{1}'.format(args.mac))
            else:
                print('Physical address of interface {0} is spoofed to {1}'.format(args.iface, mac))
        subprocess.run(['ip', 'link', 'set', args.iface, 'up'])
        if(args.verboose):
            print('Interface {0} is up'.format(args.iface))
        print('You are now anonymous. Happy cracking!')
    else:
        print('Interface {0} is not connected'.format(args.iface))

if __name__ == "__main__":
    main()
