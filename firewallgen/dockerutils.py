from __future__ import absolute_import

import docker
import logging
import psutil

_pid0_cache = {}
_pid_cache = {}

logger = logging.getLogger(__name__)


def _find_container(_parents, pid):
    if pid in _parents:
        return _parents[pid]
    process = psutil.Process(pid)
    if not process:
        return
    parents = process.parents()
    for parent in parents:
        return _find_container(_parents, parent.pid)


def _gen_pid0_cache():
    client = docker.from_env()
    containers = client.containers.list()
    result = {}
    for container in containers:
        container.reload()
        result[container.attrs["State"]["Pid"]] = container
    return result


def find_container(pid):
    global _pid0_cache
    global _pid_cache
    if not _pid0_cache:
        _pid0_cache = _gen_pid0_cache()
    if pid not in _pid_cache:
        _pid_cache[pid] = _find_container(_pid0_cache, pid)
    return _pid_cache[pid]


def pid_to_name(pid):
    result = find_container(pid)
    if not result:
        return
    return result.name


def _lookup_bridge_name(network):
    client = docker.from_env()
    try:
        network = client.network.get(network)
    except docker.errors.NotFound as _:
        logger.info("network %s not found" % network)
        return
    options = network["Options"]
    if "com.docker.network.bridge.name" not in options:
        return
    return options["com.docker.network.bridge.name"]


def _parse_port(port_proto_str):
    split = port_proto_str.split("/")
    port = split[0]
    proto = split[1]
    return port, proto


def get_network_meta(pid):
    container = find_container(pid)
    # This port could be restricted to one of the networks - we don't
    # handle that yet
    ports = container.attrs["NetworkSettings"]["Ports"]
    if not ports:
        return
    networks = container.attrs["NetworkSettings"]["Networks"]
    bridges = set()
    for network in networks:
        bridge = _lookup_bridge_name(network["NetworkID"])
        if not bridge:
            continue
        bridges.add(network)
    bridges = list(bridges)
    return [
        {
            "port": _parse_port(x)[0],
            "bridges": bridges,
        } for x in ports
    ]
