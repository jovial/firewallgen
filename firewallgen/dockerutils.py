from . import utils

import re


def _process_cgroup_line(line):
    m = re.search("docker/(?P<id>.*)", line)
    if m:
        return m.group("id")


def pid_to_container_id(pid):
    cgroup_path = "/proc/{pid}/cgroup".format(pid=pid)
    with open(cgroup_path) as f:
        return _cgroup_lines_to_container_id(f)


def _cgroup_lines_to_container_id(cgroup_lines):
    for line in cgroup_lines:
        container_id = _process_cgroup_line(line)
        if container_id:
            return container_id
    return None


def _clean_container_name_docker_output(output):
    m = re.search("'/(?P<container>.*)'", output)
    if m:
        return m.group("container")


def container_id_to_name(id_, cmdrunner=utils.CmdRunner()):
    if not id_:
        return None
    cmd = ['docker', 'inspect', '--format', "'{{.Name}}'", id_]
    try:
        output = cmdrunner.check_output(cmd)
    except OSError:
        # Could be the case if docker not installed
        return None
    return _clean_container_name_docker_output(output)


def pid_to_name(pid, cmdrunner=utils.CmdRunner()):
    id_ = pid_to_container_id(pid)
    return container_id_to_name(id_, cmdrunner=cmdrunner)
