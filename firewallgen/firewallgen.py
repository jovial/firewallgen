from iputils import ipv6_mapped_to_ipv4
from . import ssutils
from . import iputils
from . import dockerutils


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


class InterfaceMap(object):

    def __init__(self, ip_to_interface_map={}):
        self.interface_map = iputils.get_ip_to_interface_map()
        self.ip_to_interface_map = ip_to_interface_map

    def get(self, addr):
        interface = self.ip_to_interface_map.get(addr, None)
        if not interface:
            # sometimes a process can report to be listening on an ip
            # without a corresponding interface
            if addr in self.interface_map:
                interface = self.interface_map[addr]
        if not interface:
            interface = "unknown"
        return interface


class AbstractCollector(object):
    def __init__(self, proto, interface_finder):
        self.proto = proto
        if not proto or proto not in ["tcp", "udp"]:
            raise ValueError("proto must be one of: tcp, udp")
        self.interface_finder = interface_finder


class AbstractIPV4Collector(AbstractCollector):

    def create_socket(self, addr, port, processes):
        if addr == '*':
            interface = "all"
            addr = None
        elif addr.startswith('*%'):
            # e.g *%breno1.71
            # notes: I think % is the interface separator - so may need
            # an interface list, for now just listen to all (the * in
            # *%breno1.71)
            interface = "all"
            addr = None
        else:
            interface = self.interface_finder.get(addr)
        return [OpenSocket(addr, port, interface, self.proto, processes)]


class AbstractIPV4MappedIPV6Collector(AbstractCollector):

    def create_socket(self, addr, port, processes):
        interface = "lo"
        if addr == '::':
            interface = "all"
            addr = None
        elif addr == '::1':
            interface = "lo"
            addr = "127.0.0.1"
        elif '%' in addr:
            # e.g *%breno1.71
            # notes: I think % is the interface separator - so may need
            # an interface list, for now just listen to all (the * in
            # *%breno1.71)
            interface = "all"
            addr = None
        else:
            # convert ipv4-mapped-ipv6 to ipv4 before lookup
            addr = ipv6_mapped_to_ipv4(addr)
            interface = self.interface_finder.get(addr)
            if interface == "unknown":
                return []
        return [OpenSocket(addr, port, interface, self.proto, processes)]


class TCPDataCollector(AbstractIPV4Collector):
    def __init__(self, interface_finder=InterfaceMap()):
        super(TCPDataCollector, self).__init__("tcp", interface_finder)

    def get_ss_output(self):
        return ssutils.get_tcp_listening()


class UDPDataCollector(AbstractIPV4Collector):

    def __init__(self, interface_finder=InterfaceMap()):
        super(UDPDataCollector, self).__init__("udp", interface_finder)

    def get_ss_output(self):
        return ssutils.get_udp_listening()


class TCPDataCollectorIPV4Mapped(AbstractIPV4MappedIPV6Collector):

    def __init__(self, interface_finder=InterfaceMap()):
        super(TCPDataCollectorIPV4Mapped, self).__init__(
            "tcp", interface_finder)

    def get_ss_output(self):
        return ssutils.get_tcp_listening(version=6)


class UDPDataCollectorIPV4Mapped(AbstractIPV4MappedIPV6Collector):

    def __init__(self, interface_finder=InterfaceMap()):
        super(UDPDataCollectorIPV4Mapped, self).__init__(
            "udp", interface_finder)

    def get_ss_output(self):
        return ssutils.get_udp_listening(version=6)


def collect_open_sockets(collector, docker_hinter=dockerutils.pid_to_name):
    sockets = []
    records = ssutils.parse_ss_output(collector.get_ss_output())
    for record in records:
        listen_tuple = record['Local Address:Port']
        addr, port = iputils.do_parse_port(listen_tuple)
        processes = set()
        try:
            processes_raw = record['Extras']['users']
        except KeyError:
            processes_raw = []
        for process in processes_raw:
            docker_hint = docker_hinter(process['pid'])
            process = Process(process['name'], docker_hint)
            processes.add(process)
        if not processes:
            process = Process("unknown", None)
            processes.add(process)
        socket = collector.create_socket(addr, port, processes)
        if socket:
            sockets.extend(socket)
    return sockets

