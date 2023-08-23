'''
pyshark 라이브러리 활용해서 특정 네트워크 인터페이스 실시간 캡쳐후

wireshark 같이 헤더 및 데이터 구분하여 출력해주는 도구 만들기
'''
import pyshark 

cap = pyshark.LiveCapture(interface="이더넷", use_json=True, include_raw= True) 

cap.sniff(packet_count=10, timeout=40) #패킷 10개 또는 40초 경과 하면 캡쳐 결과 반환


data = cap[0]

#raw_packet = data.get_raw_packet().hex()
raw_packet = 'ffffffffffff00d0cb791e5b0806000108000604000100d0cb791e5b7305c3fe0000000000007305c3d7e90fc86e0000000000000000000000000000'
eth_header = raw_packet[:28]    # 0~28즉 14byte 가 이더넷 해더
pack_type = eth_header[24:28]   # 페킷의 타입에 따라 보여주는 모양이 달라야 된다.

if pack_type == '0800':  #IP
    print('IP Type')

elif pack_type == '0806':   #ARP
    des_arp = eth_header[:12]
    src_arp = eth_header[12:24]
    trailer = raw_packet[84:]

    arp = raw_packet[28:84]
    hardware_type = arp[:4]

    print('ARP type')
    if len(raw_packet) == 120: #ARP LEPLY packet
        print('ARP replay')
        print(f'des_ARP: {des_arp}')
        print(f'src_ARP: {src_arp}')
        print(f'Trailer: {trailer}')


    else: #ARP request
        print('ARP request')


elif pack_type == '9000':   #loopback
    print('loopback type')


'''


print(f'pack_type: {pack_type}')
print(f'ETH_LAYER')
print(f'Destination: {des_arp}')
print(f'Source     : {src_arp}')
if pack_type == '0806':
    print(f'Type       : ARP (0x{pack_type})')

    if len(raw_packet) == 120:
        print(True)




elif pack_type == '0800':
    print(f'Type       : IPv4 (0x{pack_type})')

elif pack_type == '9000':
    print(f'Type       : Loopback (0x{pack_type})')
'''
'''
b'E\x00\x00(\x00\x00@\x00@\x06\x00\x00s\x15\x98T\x7f\x00\x00\x01\xb6\x1e\x00\xa1\x00\x00\x00\x00\x00\x00\x00\x00P\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
print(f'ETH_LAYER')
print(f'Destination: ',data.get_raw_packet()[:5])
print(f'Source:      ',data.get_raw_packet()[6:12])
'''
