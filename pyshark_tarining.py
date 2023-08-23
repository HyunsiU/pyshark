'''
pyshark 라이브러리 활용해서 특정 네트워크 인터페이스 실시간 캡쳐후

wireshark 같이 헤더 및 데이터 구분하여 출력해주는 도구 만들기
'''
import pyshark 
from arp_hardware_type import hardware_type
from ip_type import protocol_type
import struct
import socket


cap = pyshark.LiveCapture(interface="이더넷", use_json=True, include_raw= True) 

cap.sniff(packet_count=10, timeout=40) #패킷 10개 또는 40초 경과 하면 캡쳐 결과 반환


data = cap[0]

raw_packet = data.get_raw_packet().hex()
#raw_packet = 'ffffffffffff00d0cb791e5b0806000108000604000100d0cb791e5b73050cfe00000000000073050cc3d7e90fc86e0000000000000000000000000000'
eth_header = raw_packet[:28]    # 0~28즉 14byte 가 이더넷 해더
pack_type = eth_header[24:28]   # 페킷의 타입에 따라 보여주는 모양이 달라야 된다.

if protocol_type[pack_type] == 'ARP': #ARP일 경우

    des_mac = raw_packet[:12]       #des_mac는 6byte 글자수는 *2
    src_mac = raw_packet[12:24]     #src_mac는 6byte 글자수는 *2 
    eth_type = raw_packet[24:28]    #eth_type의 type
    pkt_hw_type = raw_packet[28:32] #패킷의 Hardware type
    pkt_pt_type = raw_packet[32:36] #패킷의 protocol_type
    hardware_size = raw_packet[36:38]
    protocol_size = raw_packet[38:40]
    opcode = raw_packet[40:44]      #arp의 opcode ; 1이면 request  2면 reply
    sender_mac_add = raw_packet[42:56]  # 보낸사람의 mac address
    sender_ip_add = raw_packet[56:64]   # 보낸사람의 ip address
    tartget_mac_add = raw_packet[64:76] # 타겟 mac address
    tartget_ip_add = raw_packet[76:84]  # 타겟 ip address

    
    
    print(f'Destination   : {des_mac}')
    print(f'source        : {src_mac}')
    print(f'eth_type      :',protocol_type[pack_type] )
    if opcode == '0001': #opcode가 1이면 trailer가 붙는다
        trailer = raw_packet[84:]
        print(f'Trailer       : {trailer}')
    print(f'Hardwre type  :',hardware_type[pkt_hw_type])
    print(f'Protocol type :',protocol_type[pkt_pt_type])
    print(f'hardware size : {hardware_size}')
    print(f'protocol size : {protocol_size}')
    print(f'Opcode        : {opcode}')
    print(f'Sender MAC address : {sender_mac_add}')
    print(f'Sender IP adrres   :',socket.inet_ntoa(struct.pack(">L", int(sender_ip_add, 16)))) # struct.pack-> 바이트를 압축된 이진데이터로 해석 ">"빅인디언, "L" 부호가 없는 문자 형식
    print(f'Target MAC address : {tartget_mac_add}')
    print(f'Target IP address  :',socket.inet_ntoa(struct.pack(">L", int(tartget_ip_add, 16)))) #socket.inet_ntoa -> 32비트 압축 ipv4 주소 

    
        

elif protocol_type[pack_type] == 'IPv4':
    print('IPv4 is true')
    # 여기서부터 하면됨