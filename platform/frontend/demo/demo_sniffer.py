import asyncio
import websockets
import threading
import time
import json
from scapy.all import *
sniffing = [True]
sniffer_iface = "ens33"  # 默认接口
buff = []  # 全局变量
sent=[0]
serial=[0]

def sniffer_send(packet_dict):
    send_message(message=packet_dict,source="sniffer",message_type="server_speak")

def print_packet_info(packet_dict):
    print(packet_dict)

def sniff_packets():
    while True:
        sniff(iface=sniffer_iface, prn=sniffer_packet_callback, filter="ip or arp or ip6", store=0, count=10)
        time.sleep(0.055)

def sniffer_packet_callback(packet):
    # 创建一个字典来存储数据包信息
    packet_dict = {}

    # 获取数据包的时间戳
    packet_dict['time'] = packet.time

    # 处理IPv6数据包
    if IPv6 in packet:
        packet_dict['src'] = packet[IPv6].src
        packet_dict['dst'] = packet[IPv6].dst
        packet_dict['protocol'] = 'IPv6'
        packet_dict['info'] = packet.summary()

    # 处理IPv4数据包
    elif IP in packet:
        packet_dict['src'] = packet[IP].src
        packet_dict['dst'] = packet[IP].dst
        packet_dict['protocol'] = 'IP'
        packet_dict['info'] = packet.summary()

        if TCP in packet:
            packet_dict['protocol'] = 'TCP'
        elif UDP in packet:
            packet_dict['protocol'] = 'UDP'
        elif ICMP in packet:
            packet_dict['protocol'] = 'ICMP'

    # 处理ARP数据包
    elif ARP in packet:
        packet_dict['src'] = packet[ARP].psrc
        packet_dict['dst'] = packet[ARP].pdst
        packet_dict['protocol'] = 'ARP'
        packet_dict['info'] = packet.summary()

    # 使用send函数发送数据包信息
    sniffer_send(packet_dict)

    # 打印数据包信息
    print_packet_info(packet_dict)

def send_message(message,source,message_type):
    package={
        "source":source,
        "message_type":message_type,
        "message":message
    }
    buff.append(package)
    serial[0]+=1

threading.Thread(target=sniff_packets).start()  # 创建一个新的线程运行函数sn()

async def echo(websocket, path):
    async def recv():
        while True:
            message = await websocket.recv()  # 监听js传来的信息
            data = json.loads(message)
            reply=dict_analysis(data)
            await websocket.send(json.dumps(reply))
            print(data["type"])
            print(f"< {message}")  # print出来

    async def send():
        while True:
            if buff and sniffing[0] :
                message = buff.pop(-1)  # 如果buff不为空，取出第一个元素
                await websocket.send(json.dumps(message))  # 通过websocket传给js
                sent[0]+=1
            await asyncio.sleep(0.05)

    recv_task = asyncio.ensure_future(recv())
    send_task = asyncio.ensure_future(send())
    done, pending = await asyncio.wait(
        [recv_task, send_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    for task in pending:
        task.cancel()


def dict_analysis(dict):
    message=""
    if dict["source"]=="sniffer":
        if dict["type"]=="start":
            message="sniffer_start"
            sniffing[0]=True
            print(message)
        elif dict["type"]=="stop":
            message="sniffer_stop"
            sniffing[0]=False
            print(message)
        elif dict["type"]=="package":
            pass
    # elif dict["source"]=="crypt":
    #     if dict["type"]=="RSA_encrypt":
    #         RSA_encrypt(message, len_secret_key)
    #     elif dict["type"]=="RSA_encrypt":
    #         RSA_encrypt(message, len_secret_key)
    elif dict["source"]=="snmp":
        if dict["type"]=="start":
            print("snmp_start")
            message="snmp_start"
        elif dict["type"]=="stop":
            pass
        elif dict["type"]=="package":
            pass
    return {
        "message_type":"server_reply",
        "message":message
    }
    

server = websockets.serve(echo, "0.0.0.0", 8766)
asyncio.get_event_loop().run_until_complete(server)
asyncio.get_event_loop().run_forever()
