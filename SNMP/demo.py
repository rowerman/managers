import subprocess
import locale

def execute_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error occurred: {stderr.decode(locale.getpreferredencoding())}")
    else:
        print(f"Output: {stdout.decode(locale.getpreferredencoding())}")

execute_command("dir")