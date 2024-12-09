from termcolor import cprint # type: ignore
import subprocess
import sys

COMMANDS = [
    #-- Linux
    #   'iptables -F',
    #   'iptables --policy FORWARD ACCEPT',
    #   'sysctl -w net.ipv4.ip_forward=1'

    #-- MAC OS
    # 'pfctl -Fa -f /etc/pf.conf',
    # 'pfctl -e',
    'sysctl -w net.inet.ip.forwarding=1'
    # sysctl net.inet.ip.forwarding           -- VERIFY MAC

]

def run():
    print('Configuring attacker machine as a router...')
    for c in COMMANDS:
        cprint(f'Executing {c}', 'light_grey', attrs=['dark'])
        command = subprocess.run(c.split(), stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)

        if command.returncode != 0:
            print(f'Error in executing: {c}')
            sys.exit(1)
