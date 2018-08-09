from . import ssutils
from . import iputils
from . import dockerutils
from . import utils
from jinja2 import Template

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

import os

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


class Process(object):
    def __init__(self, name, docker_hint=None):
        self.docker_hint = docker_hint
        self.name = name

    def __repr__(self):
        return "Process(name:{}, docker_container:{})".format(self.name,
                                                              self.docker_hint)

    def __eq__(self, other):
        return self.name == other.name and \
               self.docker_hint == other.docker_hint

    def __hash__(self):
        hash_ = hash(self.name)
        if self.docker_hint:
            hash_ += hash(self.docker_hint)
        return hash_


class OpenSocket(object):
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


class TCPDataCollector(object):
    def get_ss_output(self):
        return ssutils.get_tcp_listening()

    def create_socket(self, ip, port, interface, processes):
        return OpenSocket(ip, port, interface, "tcp", processes)


class UDPDataCollector(object):
    def get_ss_output(self):
        return ssutils.get_udp_listening()

    def create_socket(self, ip, port, interface, processes):
        return OpenSocket(ip, port, interface, "udp", processes)

def collect_open_sockets(collector, ip_to_interface_map,
                         docker_hinter=dockerutils.pid_to_name,
                         cmdrunner=utils.CmdRunner()):
    sockets = []
    records = ssutils.parse_ss_output(collector.get_ss_output())
    interface_map = None
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
        elif addr.startswith('*%'):
            interface = addr.lstrip('*%')
            addr = None
        else:
            interface = ip_to_interface_map.get(addr, None)
            if not interface:
                if not interface_map:
                    interface_map = iputils.get_ip_to_interface_map(cmdrunner)
                interface = interface_map[addr]
        socket = collector.create_socket(addr, port, interface, processes)
        sockets.append(socket)
    return sockets


def gen_firewall(sockets):
    with open('{}/firewall.j2'.format(TEMPLATE_DIR)) as f:
        tmpl = Template(f.read())
    return tmpl.render(
        firewall_rules=sockets
    )

