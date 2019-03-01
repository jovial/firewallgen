import re


def get_service(ip, port, cfg):
    term = "{}:{}".format(ip, port)
    with open(cfg) as f:
        lines = f.readlines()
        addr = None
        for line in lines:
            if re.search("^listen", line):
                addr = line.split()[1]
            if term in line:
                return addr


def get_hinter(cfg="/etc/kolla/haproxy/haproxy.cfg"):
    def wrapper(*args, **kwargs):
        return get_service(*args, cfg=cfg, **kwargs)
    return wrapper