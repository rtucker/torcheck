#!/usr/bin/python

# Checks to see if an IP address might be a Tor exit node.

# Version 1.0
# Ryan Tucker <rtucker@gmail.com> 2008/04/10

# Latest version at:
#  http://www.hoopycat.com/~rtucker/src/torcheck.py

# Uses:
#  http://exitlist.torproject.org/

# Requires:
# http://www.dnspython.org/examples.html
#  rpmforge package python-dns
#  ubuntu package python-dnspython (NOT python-dns!)

# Basic Usage:
# >>> import torcheck
# >>> tor = torcheck.torcheck()
# >>> tor.query('85.31.186.104')
# True
# >>> tor.query('2.4.6.8')
# False
# >>> tor.query('bananas')
# Traceback (most recent call last):
#   File "<stdin>", line 1, in ?
#   File "torcheck.py", line 41, in query
#     querystring = self.reverse_ip(remoteip) + '.' + myport + '.' + self.reverse_ip(myip) + '.' + basehostname
#   File "torcheck.py", line 37, in reverse_ip
#     raise TypeError, ip + ' is not an IP address'
# TypeError: bananas is not an IP address

# Bugs remaining:
# None, afaik

# Copyright (c) 2008, Ryan Tucker <rtucker@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the author (Ryan Tucker) nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY RYAN TUCKER ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL RYAN TUCKER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

basehostname = 'ip-port.exitlist.torproject.org'

import dns.resolver
import re
import socket
import string

class torcheck:
	def is_ip(self, candidate):
		# Determines whether or not candidate is an IP address.
		# Returns True if it is, False if it is not.
		# from http://www.txt2re.com/
		re1='((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?![\\d])'	# IPv4 IP Address 1
		rg = re.compile(re1,re.IGNORECASE|re.DOTALL)
		m = rg.search(candidate)
		if m: return True 
		else: return False

	def reverse_ip(self, ip, af='ipv4'):
		# Turns that IP address right round, baby, right round.
		# e.g. input 1.2.3.4 -> output 4.3.2.1
		# af should be ipv4; in the future, this might do ipv6.

		# this is an ip address, right?
		if self.is_ip(ip):
			dq = string.split(ip, '.')
			dq.reverse()
			return string.join(dq, '.')
		else:
			raise(TypeError, ip + ' is not an IP address')

	def query(self, remoteip, myip=None, myport='80'):
		# Queries the exitlist to see if the IP address might have
		# connected here.

		# Requires: remoteip (the IP address you want to check on)
		# May take: myip (the local IP address), myport (the local port)

		# If no myip, guess!
		if myip == None:
			myip = socket.gethostbyname(socket.gethostname())
			if myip == '127.0.0.1':
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				s.connect(('192.168.254.254', 0))
				myip = s.getsockname()[0]
		# Build the hostname to search
		querystring = self.reverse_ip(remoteip) + '.' + myport + '.' + self.reverse_ip(myip) + '.' + basehostname
		q = dns.resolver.Resolver()
		# timeout in 5 seconds
		q.lifetime = 5.0
		try: response = q.query(querystring, 'A').rrset[0].to_text()
		except dns.resolver.NXDOMAIN: return False
		except dns.exception.Timeout: return False
		if response == '127.0.0.2':
			return True
		else:
			raise(KeyError, 'Unknown response ' + response)

def main():
	import sys
	if len(sys.argv) < 2:
		print('usage: ' + sys.argv[0] + ' <remote ip address> [<port> [<local ip address>]]')
		sys.exit(1)
	remoteip = sys.argv[1]
	try:
		localip = sys.argv[3]
	except:
		localip = None
	try:
		port = sys.argv[2]
	except:
		port = '80'
	validator = torcheck()

	print(validator.query(remoteip, localip, port))

if __name__ == "__main__":
	main()

