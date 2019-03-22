from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii

def Check(str_):
	str_ = bytearray(str_)
	csum = 0
	countTo = (len(str_) // 2) * 2

	for count in range(0, countTo, 2):
		thisVal = str_[count+1] * 256 + str_[count]
		csum = csum + thisVal
		csum = csum & 0xffffffff

	if countTo < len(str_):
		csum = csum + str_[-1]
		csum = csum & 0xffffffff

	csum = (csum >> 16) + (csum & 0xffff)
	#csum = csum + (csum >> 16)
	answer = ~csum
	#for sure for 16 bit
	answer = answer & 0xffff
	#difference between big and little endian
	answer = answer >> 8 | (answer << 8 & 0xff00)
	return answer

flag = 0
hops = 30
left = 5.0
tout = 5.0
name = sys.argv[1]
dest = socket.gethostbyname(name)

seq = 3

print ("traceroute to %s (%s), %d hops max" % (name, dest, hops), end = '')
for ttl in range(1, hops + 1):
	for k in range(3):

		### create socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_ICMP)
		sock.setsockopt(socket.SOL_IP, socket.IP_TTL, struct.pack('I', ttl))
		sock.settimeout(tout)

		### send packet
		checksum = 0
		pid = os.getpid() & 0xFFFF
		head = struct.pack("bbHHh", 8, 0, checksum, pid, seq)
		data = struct.pack("d", time.time())

		checksum = Check(head + data)
		checksum = htons(checksum)

		head = struct.pack("bbHHh", 8, 0, checksum, pid, seq)
		send = head + data

		sock.sendto(send, (dest, 0))


		### recv packet
		strt = time.time()
		temp = select.select([sock], [], [], tout)		# server socket, client socket, error message, time left => ready temp list
		if k == 0: print("\n%3d  " % (ttl), end = '')
		if temp[0] == []:
			print("*    ", end = '')
			continue

		recv, addr = sock.recvfrom(65536)
		recvtime = time.time()

		# left = left - (done - strt)
		# if left <= 0:
		# 	print("*    ", end = '')
		# 	break

		head = recv[20:28]
		reqt, code, checksum, packetID, sequence = struct.unpack("bbHHh", head)

		orihead = recv[48:56]
		orireqt, oricode, orichecksum, oripacketID, orisequence = struct.unpack("bbHHh", orihead)
		
		if (seq != orisequence): continue

		if (reqt == 0 or reqt == 3 or reqt == 11):
			byte = struct.calcsize("d")
			sendtime = struct.unpack("d", recv[28:28 + byte])[0]
			if k == 0: print("%s" % (addr[0]), end = '  ')
			
			if reqt == 0: print("%.3f ms" % ((recvtime - sendtime) * 1000), end = '  ')
			if reqt == 3: print("%.3f ms" % ((recvtime - strt) * 1000), end = '  ')
			if reqt == 11: print("%.3f ms" % ((recvtime - strt) * 1000), end = '  ')
			
			if reqt == 0 : flag += 1

		seq += 1
	sock.close()
	if flag == 3: break

print()