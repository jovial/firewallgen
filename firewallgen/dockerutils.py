from __future__ import absolute_import
from firewallgen import utils

from itertools import chain
import re

import docker

_pid_cache = {}


def _get_pids(container):
    raw = container.top(ps_args="-eo pid")
    return list(chain.from_iterable(raw["Processes"]))


def _gen_cache():
    client = docker.from_env()
    containers = client.containers.list()
    result = {}
    for container in containers:
        for pid in _get_pids(container):
            result[int(pid)] = container.name
    return result


def pid_to_name(pid, cmdrunner=utils.CmdRunner()):
    global _pid_cache
    if not _pid_cache:
        _pid_cache = _gen_cache()
    if pid not in _pid_cache:
        return None
    return _pid_cache[pid]

