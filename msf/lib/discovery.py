from typing import Dict, Tuple
from nmap import PortScanner
import logging
import json

# Host discovery functions.
class Discovery:

    # constructor
    def __init__(self, logger=logging):
        self.logger = logger

    # Scan for open ports (and services if specified) on given host.
    def get_ports(self, host, services_scan=True, ports='1-65535', opts='-Pn', speed=4):
        nm = PortScanner()
        opts = '{} -T{}'.format(opts, speed)
        if services_scan:
            opts = '{} -sV'.format(opts)
        else:
            opts = '{} -sS'.format(opts)
        results = nm.scan(hosts=host, ports=ports, arguments=opts)
        ports_details = results['scan']
        self.logger.debug(json.dumps(ports_details, indent=2))
        return ports_details

    # Scan for OS details of provided hosts.
    def get_os(self, host, opts='-Pn', speed=4, sudo=True):
        nm = PortScanner()
        results = nm.scan(hosts=host, arguments='-O {} -T{}'.format(opts, speed), sudo=sudo)
        host_details = results['scan']
        self.logger.debug(json.dumps(host_details, indent=2))
        return host_details

    # Run discovery functions on the specified host.
    def do_discovery(self, host, ports='1-65535', opts='-Pn', sudo=False):
        nm = PortScanner()
        self.logger.info('[!] Checking to make sure host {} is reachable.'.format(host))
        results = nm.scan(hosts=host, arguments='-PE -n -sn')
        if len(list(results['scan'].keys())) < 1:
            self.logger.error('[-] Error, I was unable to reach host {}.'.format(host))
            return None, None
        self.logger.info('[!] Scanning ports {} on host {}.'.format(ports, host))
        ports_details = self.get_ports(host, ports=ports, opts=opts)
        self.logger.info('[+] Determining OS of host {}.'.format(host))
        os_details = self.get_os(host, opts=opts, sudo=sudo)
        return ports_details, os_details
