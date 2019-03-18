import subprocess


class CmdRunner:
    def check_output(self, *args, **kwargs):
        output = subprocess.check_output(*args, **kwargs)
        return output


def call_if_has(object, method, *arg, **kwargs):
    if hasattr(object, method):
        meth = object.__getattribute__(method)
        meth(*arg, **kwargs)


def is_ipv4_mapped_ipv6_enabled():
    output = subprocess.check_output(["sysctl", "net.ipv6.bindv6only",
                                     "--values"])
    return int(output) == 0
