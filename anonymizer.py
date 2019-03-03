#!/usr/bin/python3
import sys
import subprocess
import argparse
import re
import random

macRegExp = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})')


def main():
    # Command-Line argument parser
    parser = argparse.ArgumentParser(description='''Anonymizes network interfaces by
                spoofing hostnames and physical address( MAC address)''')
    generalOpt = parser.add_argument_group('General Options')
    generalOpt.add_argument('-i', '--iface', type=str, metavar='', required=True,
                            help='Interface to anonymize')
    macAddrOpt = parser.add_argument_group('MAC Address Options')
    macAddrOptExcl = macAddrOpt.add_mutually_exclusive_group(required=True)
    macAddrOptExcl.add_argument('-m', '--mac', type=macaddr, metavar='',
                                help='Physical address (MAC address) to spoof.')
    macAddrOptExcl.add_argument('-r', '--random', action='store_true',
                                help='Interface is spoofed to random MAC address')
    macAddrOptExcl.add_argument('-p', '--permanent', action='store_true',
                                help='Revert to permanent MAC address and Hostname')
    hostnameOpt = parser.add_argument_group('Hostname Options')
    hnOptExcl = hostnameOpt.add_mutually_exclusive_group()
    hnOptExcl.add_argument('-rhn', '--randomhost', action='store_true',
                           help='Hostname changed to a random name')
    hnOptExcl.add_argument('-hn', '--hostname', type=str, metavar='',
                           help='Hostname to change')
    printOpt = parser.add_argument_group('Print Options')
    printOptExcl = printOpt.add_mutually_exclusive_group()
    printOptExcl.add_argument('-q', '--quiet', action='store_true',
                              help='Prints only MAC and hostname')
    printOptExcl.add_argument('-v', '--verboose', action='store_true',
                              help='Prints everything happening in the process')
    global args
    args = parser.parse_args()

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

    # Changing hostname
    if (args.hostname or args.randomhost):
        changeHostname()

    # Spoofing MAC address
    if (args.iface in ifaceList):
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
            changeMacPerm()
        elif args.mac != '':

            # MAC change function
            changeMac()

        # Interface Up
        subprocess.run(['ip', 'link', 'set', args.iface, 'up'])
        printv('Interface {0} is up'.format(args.iface))

        print('Anonymizer thanks you')
    else:
        print('Interface {0} is not connected'.format(args.iface))


def macaddr(s, pat=macRegExp):
    if not pat.match(s):
        print('''MAC address should be in format
                 XX:XX:XX:XX:XX:XX [0-9 a-f A-F]''')
        raise argparse.ArgumentTypeError
    return s


def printv(msg):
    if args.verboose:
        print(msg)


def changeHostname():

    if args.randomhost is True:
        # Hostname generator
        proc = subprocess.run(['./genhost', '1'], stdout=subprocess.PIPE)
        host = proc.stdout.decode('utf-8')[:-1]

    # setting up a new random hostname
    subprocess.run(['hostnamectl', 'set-hostname', host])
    print('Hostname changed to {0}'.format(host))
    print()


def changeMac():

    # MAC address spoofing through ip command
    subprocess.run(['ip', 'link', 'set', args.iface, 'address', args.mac])
    if args.quiet:
        print('{1}'.format(args.mac))
    else:
        print('MAC address of interface {0} is spoofed to {1}'.format(
            args.iface, args.mac))


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
        print('{1}'.format(args.mac))
    else:
        print('MAC address of interface {0} is spoofed to {1}'.format(
            args.iface, mac))
        print()


def changeMacPerm():
    mac = 'e4:a7:a0:43:6a:48'
    hostname = 'MegaByte'
    subprocess.run(['ip', 'link', 'set', args.iface, 'address', mac])
    subprocess.run(['hostnamectl', 'set-hostname', hostname])
    print('MAC address reverted to {0}'.format(mac))
    print('Hostname reverted to {0}'.format(hostname))


if __name__ == "__main__":
    main()
