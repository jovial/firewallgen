import fileinput
import re

from .utils import call_if_has

try:
    # python three only
    import ipaddress
except ImportError:
    pass


def do_parse_port(line):
    split = line.split(":")
    addr = ":".join(split[0:-1])
    port = int(split[-1])
    return addr, port


def get_ip_to_interface_map(cmdrunner):
    raw = cmdrunner.check_output(["ip", "-o", "addr"])
    if isinstance(raw, str):
        raw = iter(raw.splitlines())

    ip_map = {}
    for line in raw:
        fields = re.split('\s+', line)
        interface = fields[1]
        ip_and_subnet = fields[3]
        ip = ip_and_subnet.split("/")[0]
        ip_map[ip] = interface
    return ip_map


def parse_port(line, events):
    addr_raw, port = do_parse_port(line)
    try:
        addr = ipaddress.ip_address(addr_raw)
        if isinstance(addr, ipaddress.IPv4Address):
            call_if_has(events, "on_ipv4", addr, port)
        else:
            call_if_has(events, "on_ipv6", addr, port)
    except ValueError:
        if addr_raw == "*":
            call_if_has(events, "on_wildcard_ipv4", addr_raw, port)


def _to_json(addr, port):
    result = (
            '{' +
            '"address": "{addr}", "port": "{port}"'.format(addr=addr,
                                                           port=port)
            + '}'
    )
    return result


class IPV4Parser:
    first = True

    def on_start(self):
        print("[")

    def on_ipv4(self, addr, port):
        if self.first:
            self.first = False
            print(_to_json(addr, port))
        else:
            print(",")
            print(_to_json(addr, port))

    def parse(self, line):
        parse_port(line, self)

    def on_finish(self):
        print("]")


if __name__ == "__main__":

    input = fileinput.input()
    parser = IPV4Parser()
    parser.on_start()
    for line in input:
        parser.parse(line)
    parser.on_finish()
