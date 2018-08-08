import subprocess


class CmdRunner:
    def check_output(self, *args, **kwargs):
        output = subprocess.check_output(*args, **kwargs)
        return output
