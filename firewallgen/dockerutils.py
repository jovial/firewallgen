from __future__ import absolute_import

import docker
import psutil

_pid_cache = {}


def find_container(_parents, pid):
    if pid in _parents:
        return _parents[pid]
    process = psutil.Process(pid)
    if not process:
        return
    parents = process.parents()
    for parent in parents:
        return find_container(_parents, parent.pid)


def _gen_cache():
    client = docker.from_env()
    containers = client.containers.list()
    result = {}
    for container in containers:
        container.reload()
        result[container.attrs["State"]["Pid"]] = container.name
    return result


def pid_to_name(pid):
    global _pid_cache
    if not _pid_cache:
        _pid_cache = _gen_cache()
    return find_container(_pid_cache, pid)

