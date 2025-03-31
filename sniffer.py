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
		print('\nSniffer...')
		print('\nDestinoMac:{} \nOrigemMac: {} \nProtocolo de Ethernet: {}  '.format(destMac, srcMac, ethProto))
		if ethProto == 8:
			(ttl, protocoloIpv4, srcIp, destIp, tamanhoHeader, data) = pacoteIPV4(data)

			print('\nTamanhoHeader:{} \nTTL: {} \nProtocolo: {} \nOrigem {} \nDestino{} '.format(tamanhoHeader, ttl, protocoloIpv4, srcIp, destIp))

			if protocoloIpv4 == 1:
				tipoIcmp, codigo, checksum, data = pacoteICMP(data)
				print('Pacote ICMP:')
				print('\nTipo: {}\nCodigo: {}\nChecksum: {}'.format(tipoIcmp, codigo, checksum))
				print('Data: {}\n'.format(data))

			elif protocoloIpv4 == 6:
				(portaSrc, portaDest, sequencia, acknowledgement, flagsUrg, flagsAck, flagsPsh, flagsRst, flagsSyn, flagsFin, data) = protocoloTCP(data)
				print('Pacote TCP:')
				print('\nPorta de destino: {}\nPorta de origem: {}\nSequencia: {} \nACK: {}'.format(portaSrc, portaDest, sequencia, acknowledgement))
				print('\nFlags: \n URG: {}\nACK: {}\nPUSH: {} \nRST: {}\nSYN: {}\nFIN: {}'.format(flagsUrg, flagsAck, flagsPsh, flagsRst, flagsSyn, flagsFin))
				print('Data: {}\n'.format(data))

			elif protocoloIpv4 == 17:
				srcPort, destPort, size, data = protocoloUPD(data)
				print('Protocolo UDP:')
				print('\nPorta de destino: {}\n Porta de origem: {}\nTamanho: {}'.format(srcPort, destPort, size))
				print('Data: {}\n'.format(data))
			else:
				print('Data: {}\n'.format(data))
		else:
			print('Data: {}\n'.format(data))

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
	return ttl, protocoloIpv4, IPv4(srcIp), IPv4(destIp), tamanhoHeader, data[20:]

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
	return (portaSrc, portaDest, sequencia, acknowledgement, flagsAck, flagsFin, flagsPsh, flagsRst, flagsUrg, flagsSyn, data[offset:])

#ler o protocolo UDP

def protocoloUPD(data):
	srcPort, destPort, size = struct.unpack('! H H 2x H', data[:8])
	return srcPort, destPort, size, data[8:]	



main()