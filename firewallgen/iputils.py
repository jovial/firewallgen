import re
import subprocess

from utils import CmdRunner

try:
    # python three only
    import ipaddress
except ImportError:
    pass


def parse_ip_port(line):
    split = line.split(":")
    addr = ":".join(split[0:-1])
    port = int(split[-1])
    return addr, port


def ipv6_mapped_to_ipv4(addr):
    prefix = "::ffff:"
    if addr.startswith("::ffff:"):
        addr = addr[len(prefix):]
    return addr


def get_ip_to_interface_map(cmdrunner=CmdRunner()):
    raw = cmdrunner.check_output(["ip", "-o", "addr"])
    if isinstance(raw, str):
        raw = iter(raw.splitlines())

    ip_map = {}
    for line in raw:
        fields = re.split(r'\s+', line)
        interface = fields[1]
        ip_and_subnet = fields[3]
        ip = ip_and_subnet.split("/")[0]
        ip_map[ip] = interface
    return ip_map


def is_ipv4_mapped_ipv6_enabled():
    output = subprocess.check_output(["sysctl", "net.ipv6.bindv6only",
                                     "--values"])
    return int(output) == 0
