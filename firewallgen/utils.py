import subprocess


class CmdRunner:
    def check_output(self, *args, **kwargs):
        output = subprocess.check_output(*args, **kwargs)
        return output


def call_if_has(object, method, *arg, **kwargs):
    if hasattr(object, method):
        meth = object.__getattribute__(method)
        meth(*arg, **kwargs)