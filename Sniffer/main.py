import sys
from scapy.all import *

# 全局变量来控制嗅探
sniffing = False
iface = "ens33"  # 默认接口

def start():
    global sniffing
    sniffing = True

def stop():
    global sniffing
    sniffing = False

def send(packet_dict):
    # 这里是你发送数据包信息的代码...
    pass

def print_packet_info(packet_dict):
    print(packet_dict)

def sniff_packets():
    while sniffing:
        sniff(iface=iface, prn=packet_callback, filter="ip or arp or ip6", store=0, count=10)

def packet_callback(packet):
    # 创建一个字典来存储数据包信息
    packet_dict = {}

    # 获取数据包的时间戳
    packet_dict['time'] = packet.time

    # 处理IPv6数据包
    if IPv6 in packet:
        packet_dict['src'] = packet[IPv6].src
        packet_dict['dst'] = packet[IPv6].dst
        packet_dict['protocol'] = 'IPv6'
        packet_dict['info'] = packet[IPv6].show2(dump=True)

    # 处理IPv4数据包
    elif IP in packet:
        packet_dict['src'] = packet[IP].src
        packet_dict['dst'] = packet[IP].dst
        packet_dict['protocol'] = 'IP'
        packet_dict['info'] = packet[IP].show2(dump=True)

        if TCP in packet:
            packet_dict['protocol'] = 'TCP'
            packet_dict['info'] += packet[TCP].show2(dump=True)
        elif UDP in packet:
            packet_dict['protocol'] = 'UDP'
            packet_dict['info'] += packet[UDP].show2(dump=True)
        elif ICMP in packet:
            packet_dict['protocol'] = 'ICMP'
            packet_dict['info'] += packet[ICMP].show2(dump=True)

    # 处理ARP数据包
    elif ARP in packet:
        packet_dict['src'] = packet[ARP].psrc
        packet_dict['dst'] = packet[ARP].pdst
        packet_dict['protocol'] = 'ARP'
        packet_dict['info'] = packet[ARP].show2(dump=True)

    # 使用send函数发送数据包信息
    send(packet_dict)

    # 打印数据包信息
    print_packet_info(packet_dict)

def main():
    start()
    sniff_packets()
    stop()

if __name__ == '__main__':
    main()
