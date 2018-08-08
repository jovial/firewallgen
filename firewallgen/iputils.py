import fileinput
import ipaddress
import json


def do_parse_port(line):
    split = line.split(":")
    addr = ":".join(split[0:-1])
    port = int(split[-1])
    return addr, port


def _call_if_has(events, method, *arg, **kwargs):
    if hasattr(events, method):
        meth = events.__getattribute__(method)
        meth(*arg, **kwargs)


def get_ip_to_interface_map(cmdrunner):
    raw = cmdrunner.check_output('lshw -json -quiet')
    hw = json.loads(raw)
    map = {}

    def walk_children(node):
        if not isinstance(node, dict):
            return
        for child in node['children']:
            if 'children' in child:
                walk_children(child)
            if child['class'] != 'network':
                continue
            config = child['configuration']
            if 'ip' in config:
                ip = config['ip']
                map[ip] = child['logicalname']

    walk_children(hw)
    return map


def parse_port(line, events):
    addr_raw, port = do_parse_port(line)
    try:
        addr = ipaddress.ip_address(addr_raw)
        if isinstance(addr, ipaddress.IPv4Address):
            _call_if_has(events, "on_ipv4", addr, port)
        else:
            _call_if_has(events, "on_ipv6", addr, port)
    except ValueError:
        if addr_raw == "*":
            _call_if_has(events, "on_wildcard_ipv4", addr_raw, port)


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
