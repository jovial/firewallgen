import re
import glob

try:
    from collections.abc import Iterable  # noqa
except ImportError:
    from collections import Iterable  # noqa


def get_service(ip, port, cfg):
    term = "{}:{} ".format(ip, port)
    try:
        with open(cfg) as f:
            lines = f.readlines()
            addr = None
            for line in lines:
                if re.search("^listen", line):
                    addr = line.split()[1]
                if term in line:
                    return addr
    except IOError:
        pass


def get_hinter(*cfg):
    if len(cfg) == 0:
        cfg = [
            "/etc/kolla/haproxy/haproxy.cfg",
            "/etc/kolla/haproxy/services.d/*.cfg"
        ]
    else:
        cfg = list(cfg)

    def wrapper(*args, **kwargs):
        if isinstance(cfg, Iterable):
            for item in cfg:
                files = glob.glob(item)
                for f in files:
                    hint = get_service(*args, cfg=f, **kwargs)
                    if hint:
                        return hint
        else:
            return get_service(*args, cfg=cfg, **kwargs)
    return wrapper
