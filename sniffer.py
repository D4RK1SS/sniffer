import socket
import struct
import textwrap
import os
import time

def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		rawData, adrr = conn.recvfrom(65536)
		destMac, srcMac, ethProto, data = ethernetFrame(rawData)
		destIp, srcIp = pacoteIPV4(rawData)
		print('\nSniffer...')
		print('\nDestinoMac:{} \nOrigemMac: {} \nProtocolo: {}'.format(destMac, srcMac, ethProto ))
		time.sleep(0.5)
		os.system('clear')



#ler o pacote de rede
def ethernetFrame(data):
	destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
	return getMacAddr(destMac), getMacAddr(srcMac), socket.htons(proto), data[14:]

	#retorna o endereço MAC formatdo 
def getMacAddr(bytes_addr):
	bytesStr = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytesStr).upper()

#ler o ipv4
def pacoteIPV4(data):
	tamanhoHdrVersao = data[0]
	tamanhoHeader = (tamanhoHdrVersao & 15)*4
	ttl, protocoloIpv4, srcIp, destIp = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return protocoloIpv4, IPv4(srcIp), IPv4(destIp), data[tamanhoHeader:], tamanhoHeader

#formata o ipv4

def IPv4(addr):
	return '.'.join(map(str, addr))

#ler o ICMP
def pacoteICMP(data):
	tipoIcmp, codigo, checksum = struct.unpack('! B B H', data[:4])
	return tipoIcmp, codigo, checksum, data[4:]

#le o protocolo tcp

def protocoloTCP(data):
	(portaSrc, portaDest, sequencia, acknowledgement, offsetReservedFlags) = struct.unpack('! H H L L H', data[:14])
	offset = (offsetReservedFlags >> 12)*4
	flagsUrg = (offsetReservedFlags & 32) >> 5
	flagsAck = (offsetReservedFlags & 16) >> 3
	flagsPsh = (offsetReservedFlags & 8) >> 3
	flagsSyn = (offsetReservedFlags & 2) >> 1
	flagsRst = (offsetReservedFlags & 4) >> 2
	flagsFin = offsetReservedFlags & 1
	return portaSrc, portaDest, sequencia, acknowledgement, flagsAck, flagsFin, flagsPsh, flagsRst, flagsUrg, flagsSyn, data[offset:]

	



main()