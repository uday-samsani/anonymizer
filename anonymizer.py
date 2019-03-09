#!/usr/bin/python3
import sys
import os
import json
import subprocess
import argparse
import re
import random

confPath = './'
confFile = 'network.json'

macRegExp = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})')


def main():
    # Command-Line argument parser
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, max_help_position=30, width=250),
        description='''Anonymizes network interfaces by spoofing hostnames and physical address(MAC address) ''')
    generalOpt = parser.add_argument_group('General Options')
    generalOpt.add_argument('-i', '--iface', type=str, metavar='dev',
                            help='Interface to anonymize')
    generalOpt.add_argument('-u', '--update', action='store_true',
                            help='Check for updates')
    generalOpt.add_argument('-v', '--version', action='store_true',
                            help='Show ther version of current Anonymizer')
    macAddrOpt = parser.add_argument_group('MAC Address Options')
    macAddrOptExcl = macAddrOpt.add_mutually_exclusive_group()
    macAddrOptExcl.add_argument('-m', '--mac', type=macaddr, metavar='address',
                                help='Physical address (MAC address) to spoof.')
    macAddrOptExcl.add_argument('-r', '--random', action='store_true',
                                help='Interface is spoofed to random MAC address')
    macAddrOptExcl.add_argument('-p', '--permanent', action='store_true',
                                help='Revert to permanent MAC address and Hostname')
    hostnameOpt = parser.add_argument_group('Hostname Options')
    hnOptExcl = hostnameOpt.add_mutually_exclusive_group()
    hnOptExcl.add_argument('-rhn', '--randomhost', action='store_true',
                           help='Hostname changed to a random name')
    hnOptExcl.add_argument('-hn', '--hostname', type=str, metavar='host',
                           help='Hostname to change')
    printOpt = parser.add_argument_group('Print Options')
    printOptExcl = printOpt.add_mutually_exclusive_group()
    printOptExcl.add_argument('-q', '--quiet', action='store_true',
                              help='Prints only MAC and hostname')
    printOptExcl.add_argument('-V', '--verboose', action='store_true',
                              help='Prints everything happening in the process')
    global args
    args = parser.parse_args()

    if args.update:
        printv('Updating Anonymizer...')
        subprocess.run(['git', 'pull'], stdout=subprocess.PIPE)
        print('Anonymizer updated.')
        sys.exit(0)

    if args.version:
        print('Version 1.0 alpha')
        sys.exit(0)

    # Changing hostname
    if (args.hostname or args.randomhost):
        changeHostname()

    # Spoofing MAC address
    if args.iface:
        if checkIface():
            printv("Anonymizing the interface {0}".format(args.iface))

            # Restarting the network-manager to make the changes into preserve
            subprocess.run(['service', 'network-manager', 'restart'])
            printv('Network Manager restarted')

            # Interface Down
            subprocess.run(['ip', 'link', 'set', args.iface, 'down'])
            printv('Interface {0} is down'.format(args.iface))

            if args.random:

                # MAC Change random function
                changeMacRand()
            elif args.permanent:

                # Reverting to permanent MAC address and hostname
                revertPerm()
            elif args.mac != '':

                # MAC changer function
                changeMac()

            # Interface Up
            subprocess.run(['ip', 'link', 'set', args.iface, 'up'])
            printv('Interface {0} is up'.format(args.iface))

            print('Anonymizer thanks you')
        else:
            print('Invalid Interface')


def checkHostname():

    proc = subprocess.run('hostname', stdout=subprocess.PIPE)
    if proc.returncode == 0:
        hostname = proc.stdout.decode('utf-8')[:-1]
        if os.path.isfile(confPath+confFile):
            with open(confPath+confFile, 'r') as rf:
                nData = json.loads(rf.read())
            if not nData.__contains__('hostname'):
                nData['hostname'] = hostname
                with open(confPath+confFile, 'w') as wf:
                    wf.write(json.dumps(nData, indent=4))
            return True
        else:
            with open(confPath+conf, 'w') as wf:
                temp = {
                    'hostname': hostname,
                    'interfaces': []
                }
                wf.write(json.dumps(temp, indent=4))
                return True
    else:
        return False


def checkIface():
    proc = subprocess.run(['ip', '-j', 'address', 'show',
                           args.iface], stdout=subprocess.PIPE)
    if proc.returncode == 0:
        iData = json.loads(proc.stdout.decode('utf-8'))
        iData = [x for x in iData if len(x) > 1]
        if os.path.isfile(confPath+confFile):
            with open(confPath+confFile, 'r') as rf:
                nData = json.loads(rf.read())
            if not nData.__contains__('interfaces'):
                nData['interfaces'] = []
                nData['interfaces'].append(
                    {
                        'ifname': iData[0]['ifname'],
                        'address': iData[0]['address']
                    }
                )
                with open(confPath+confFile, 'w') as wf:
                    wf.write(json.dumps(nData, indent=4))
                return True
            else:
                ifList = []
                for interface in nData['interfaces']:
                    if interface['ifname'] not in ifList:
                        ifList.append(interface['ifname'])

                if iData[0]['ifname'] not in ifList:
                    nData['interfaces'].append(
                        {
                            'ifname': iData[0]['ifname'],
                            'address': iData[0]['address']
                        }
                    )
                    with open(confPath+confFile, 'w') as wf:
                        wf.write(json.dumps(nData, indent=4))
                return True
        else:
            with open(confPath+confFile, 'w') as wf:
                a = {'interfaces': []}
                a['interfaces'].append(
                    {
                        'ifname': iData[0]['ifname'],
                        'address': iData[0]['address']
                    }
                )
                wf.write(json.dumps(a, indent=4))


def changeHostname():

    # Host name chceking whether it is in json data or not
    if checkHostname():
        if args.randomhost is True:
            # Hostname generator
            proc = subprocess.run(['./genhost', '1'], stdout=subprocess.PIPE)
            host = proc.stdout.decode('utf-8')[:-1]
        elif args.hostname:
            host = args.hostname
        subprocess.run(['hostnamectl', 'set-hostname', host])
        print('Hostname changed to {0}'.format(host))
        print()


def changeMac():

    # MAC address spoofing through ip command
    proc = subprocess.run(
        ['ip', 'link', 'set', args.iface, 'address', args.mac])
    if proc.returncode == 0:
        if args.quiet:
            print('{1}'.format(args.mac))
        else:
            print('MAC address of interface {0} is spoofed to {1}'.format(
                args.iface, args.mac))
    else:
        print('{0} is Invalid MAC address.'.format(args.mac))
        sys.exit(1)


def changeMacRand():
    while True:

        # Generating a random MAC address
        temp = range(6)
        mac = ':'.join('%02x' % random.randint(0, 255) for x in temp)

        # MAC address spoofing through ip command
        proc = subprocess.run(['ip', 'link', 'set', args.iface,
                               'address', mac], stdout=subprocess.PIPE)
        if(proc.returncode == 0):
            break
        else:
            printv('{0} address is invalid. Retrying ...'.format(mac))
    if(args.quiet):
        print('{0}'.format(args.mac))
    else:
        print('MAC address of interface {0} is spoofed to {1}'.format(
            args.iface, mac))
        print()


def revertPerm():

    if os.path.isfile(confPath+confFile):
        with open(confPath+confFile, 'r') as rf:
            nData = json.loads(rf.read())
        if nData.__contains__('interfaces'):
            if len(nData['interfaces']) > 0:
                for i in nData['interfaces']:
                    if i['ifname'] == args.iface:
                        mac = i['address']
        if nData.__contains__('hostname'):
            subprocess.run(['hostnamectl', 'set-hostname', nData['hostname']])
            print('Hostname reverted to {0}'.format('MegaByte'))
        subprocess.run(['ip', 'link', 'set', args.iface, 'address', mac])
        print('MAC address reverted to {0}'.format(mac))
    else:
        print('Network information not found.')
        sys.exit(1)


def macaddr(s, pat=macRegExp):
    if not pat.match(s):
        print('''MAC address should be in format
                 XX:XX:XX:XX:XX:XX [0-9 a-f A-F]''')
        raise argparse.ArgumentTypeError
    return s


def printv(msg):
    if args.verboose:
        print(msg)


if __name__ == "__main__":
    main()
