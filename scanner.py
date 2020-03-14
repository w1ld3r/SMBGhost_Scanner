import socket
import struct
import sys
import ipaddress
import multiprocessing
import subprocess
import argparse
import re
import requests
import json


DELAY = 3
SMB_PORT = 445
SHODAN_API_KEY = ''
BASE_URL = 'https://api.shodan.io'
SHODAN_OUTPUT_FILE = 'smbghost.json'

def parse(args):
    parser = argparse.ArgumentParser(description='Vulnerable SMBv3 Search')
    parser.add_argument('-t', '--target', metavar='target', help='ip or network to querry')
    parser.add_argument('-f', '--file', metavar='file', help='file containing a target list (ip, network)', type=argparse.FileType('r'))
    parser.add_argument('-o', '--output', metavar='file', help='json file containing shodan results', type=argparse.FileType('w'))

    if len(args) == 1:
        parser.print_help()
    else:
        main(parser.parse_args())

def main(args):
    targets = set()
    try:
        if args.target:
            target = args.target
            try:
                ipaddress.ip_address(target)
                targets.add(target)
            except:
                targets = get_ips(verify_network(target), targets)
        if args.file:
            targets = read_ip_from_file(args.file, targets)
    except:
        sys.exit('[!] Input not reconize !\n')

    if targets:
        result = run(targets)

    if not result.empty():
        if SHODAN_API_KEY:
            if args.file:
                shodan_search(result, args.file)
            else:
                with open(SHODAN_OUTPUT_FILE, 'w') as f:
                    shodan_search(result, f)
        else:
            display_result(result)


def verify_network(target):
    try:
        ipaddress.ip_network(target)
        return target
    except ValueError:
        return
            
def read_ip_from_file(file, targets):
    for line in file:
        targets.add(line.replace('\n', ''))
    return targets

def get_ips(network, targets):
    if network:
        cmd = f"sudo masscan -p{SMB_PORT} {network} --max-rate 100000"
        try:
            ret = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        except:
            print('[!] Unable to perform masscan')
            sys.exit(2)
        for line in ret.stdout.readlines():
            targets.add(line.decode().split()[5])
    return targets

def scann(ip, q):
    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    try:
        sock = socket.socket(socket.AF_INET)
        sock.settimeout(DELAY)
        sock.connect(( ip,  SMB_PORT ))
        sock.send(pkt)
    except:
        return
    try:
        nb, = struct.unpack('>I', sock.recv(4))
        res = sock.recv(nb)
    except:
        return

    if not res[68:70] == b'\x11\x03':
        return
    if not res[70:72] == b'\x02\x00':
        return
    q.put(ip)

def run(targets):
    q = multiprocessing.Queue()
    for ip in targets:
        p = multiprocessing.Process(target=scann, args=(ip, q))
        p.start()
    p.join()
    return q

def display_result(q):
    while not q.empty():
        print(q.get())

def shodan_search(q, file):
    result = {'smbghost': []}
    while not q.empty():
        ip = q.get()
        data = get_host_info(ip)
        if 'error' in data:
            result['smbghost'].append({'ip': ip})
        else:
            result['smbghost'].append({
                'ip': ip,
                'city': get_city(data),
                'country': get_country(data),
                'organisation': get_org(data),
                'isp': get_isp(data),
                'last_update': get_last_update(data),
                'open_ports': get_open_ports(data),
                'domain_name': reverse_dns(ip),
                'honey_score': get_honeyscore(ip),
                'vulnerabilities': get_vulns(data)
            })
    json.dump(result, file)

def get_host_info(ip):
    uri = '/shodan/host/%s' % ip
    try:
        r = requests.get(BASE_URL+uri, params={'key':SHODAN_API_KEY})
    except:
        return
    return r.json()

def reverse_dns(ip):
    uri = '/dns/reverse?ips=%s' % ip
    try:
        r = requests.get(BASE_URL+uri, params={'key':SHODAN_API_KEY})
    except:
        return
    d = r.json()
    if 'error' in d:
        return
    return d[ip]   

def get_honeyscore(ip):
    uri = '/labs/honeyscore/%s' % ip
    try:
        r = requests.get(BASE_URL+uri, params={'key':SHODAN_API_KEY})
    except:
        return
    return r.json()

def get_city(d):
    return d['city']

def get_country(d):
    return d['country_name']

def get_org(d):
    return d['org']

def get_isp(d):
    return d['isp']

def get_last_update(d):
    return d['last_update']

def get_open_ports(d):
    return d['ports']

def get_vulns(data):
    vulns = []
    for service in data['data']:
        try:
            vulns.append(service['opts']['vulns'])
        except:
            pass
    return vulns

if __name__ == "__main__":
    parse(sys.argv)
