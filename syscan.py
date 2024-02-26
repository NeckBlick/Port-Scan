from typing import Collection, List
from random import randint, shuffle
from scapy.layers.inet import IP,TCP
from scapy.sendrecv import sr

SEQ_MAX = 2**32 - 1 # Valor de limite de bits do IPV4
LIMIT_PORT = 49151 # Limite de portas
SYN_FLAG = "S"
SYN_ACK_FLAG = SYN_FLAG + "A" 
DEFAULT_TIMEOUT = 3


def port_scan(address: str, ports: Collection[int], **kwargs) -> List[int]:
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    syns = []
    ip_layer = IP(dst=address)

    for port in ports:
        packet = ip_layer/TCP(sport=LIMIT_PORT, dport=port,seq=randint(0,SEQ_MAX), flags=SYN_FLAG)
        syns.append(packet)

    answer, _ = sr(syns, verbose=False, **kwargs)

    open_ports = []
    for stimulus, response in answer:
        if response[TCP].flags.flagrepr() == SYN_ACK_FLAG:
            open_ports.append(stimulus[TCP].dport)

    return sorted(open_ports)

ip_scan = input("Digite o endereço IP: ")
print(port_scan(ip_scan, [80,8080,21,443]))