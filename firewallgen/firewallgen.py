from . import ssutils
from . import iputils
from . import dockerutils
from . import utils
from firewallgen import utils
from jinja2 import Template

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

import os

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')

class Process:
    def __init__(self, name, docker_hint=None):
        self.docker_hint = docker_hint
        self.name = name

    def __repr__(self):
        return "Process(name:{}, docker_container:{})".format(self.name,
                                                              self.docker_hint)


class OpenSocket:
    def __init__(self, ip, port, interface, proto, processes):
        self.processes = processes
        self.proto = proto
        self.interface = interface
        self.port = port
        self.ip = ip

    def __repr__(self):
        return "OpenSocket({}, {}, {}, {})".format(self.ip, self.port,
                                                   self.interface, self.proto,
                                                   self.processes)


class TCPDataCollector:
    def get_ss_output(self):
        return ssutils.get_tcp_listening()

    def create_socket(self, ip, port, interface, processes):
        return OpenSocket(ip, port, interface, "tcp", processes)


class UDPDataCollector:
    def get_ss_output(self):
        return ssutils.get_udp_listening()

    def create_socket(self, ip, port, interface, processes):
        return OpenSocket(ip, port, interface, "udp", processes)


class AnsibleVersionMixin:
    def get_version_flag(self):
        return ssutils.get_version_flag(self.module.params['ipversion'])


class AnsibleUDPCollector(UDPDataCollector, AnsibleVersionMixin):
    def __init__(self, module):
        super().__init__()
        self.module = module

    def get_ss_output(self):
        self.module.cmd(["ss", "-nlpu", self.get_version_flag()])


class AnsibleTCPCollector(UDPDataCollector, AnsibleVersionMixin):
    def __init__(self, module):
        super().__init__()
        self.module = module

    def get_ss_output(self):
        self.module.cmd(["ss", "-nlpt", self.get_version_flag()])


def collect_open_sockets(collector, ip_to_interface_map,
                         docker_hinter=dockerutils.pid_to_name,
                         cmdrunner=utils.CmdRunner):
    sockets = []
    records = ssutils.parse_ss_output(collector.get_ss_output())
    for record in records:
        listen_tuple = record['Local Address:Port']
        addr, port = iputils.do_parse_port(listen_tuple)
        processes = set()
        processes_raw = record['Extras']['users']
        for process in processes_raw:
            docker_hint = docker_hinter(process['pid'], cmdrunner=cmdrunner)
            process = Process(process['name'], docker_hint)
            processes.add(process)
        if addr == '*':
            interface = "all"
            addr = None
        else:
            interface = ip_to_interface_map.get(addr, None)
        socket = collector.create_socket(addr, port, interface, processes)
        sockets.append(socket)
    return sockets


def gen_firewall(sockets):
    with open('{}/firewall.j2'.format(TEMPLATE_DIR)) as f:
        tmpl = Template(f.read())
    return tmpl.render(
        firewall_rules=sockets
    )


def transform_network_allocation(allocation):
    map = {}
    for label, host_to_ips in allocation.items():
        # strip off _ips suffix
        interface = "{}_interface".format(label[0:-4])
        for host, ip in host_to_ips.items():
            map[ip] = interface

    map['127.0.0.1'] = 'lo'
    return map


