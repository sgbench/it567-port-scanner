print '================================================================================'
print 'Port Scanner v1.0, by Spencer Bench'
print '================================================================================'

import argparse
from scapy.all import *

# Converts the given dotted decimal string to a 32-bit integer address.
def dottedDecimalToInt(dottedDecimal):
	bytes = [int(dec) for dec in dottedDecimal.split('.')]
	addr = bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]
	return addr

# Converts the given 32-bit integer address to a dotted decimal string.
def intToDottedDecimal(addr):
	bytes = []
	bytes.append((addr & 0xFF000000) >> 24)
	bytes.append((addr & 0x00FF0000) >> 16)
	bytes.append((addr & 0x0000FF00) >> 8)
	bytes.append(addr & 0x000000FF)
	return '.'.join([str(byte) for byte in bytes])

# Parses string representations of hosts, ports, and protocols.
class TargetParser(object):

	def __init__(self):
		self.hosts = set()
		self.ports = set()
		self.proto = set()

	def parseHosts(self, hosts):
		for entry in hosts.split(','):
			if '/' in entry:
				# TODO: Support for CIDR notation?
				pass
			elif '-' in entry:
				parts = entry.split('-')
				start = dottedDecimalToInt(parts[0])
				stop = dottedDecimalToInt(parts[1])
				for host in range(start, stop + 1):
					self.hosts.add(host)
			else:
				self.hosts.add(dottedDecimalToInt(entry))

	def getHosts(self):
		hosts = []
		for h in self.hosts:
			hosts.append(h)
		return hosts

	def parsePorts(self, ports):
		for entry in ports.split(','):
			if '-' in entry:
				parts = entry.split('-')
				start = int(parts[0])
				stop = int(parts[1])
				for port in range(start, stop + 1):
					self.ports.add(port)
			else:
				self.ports.add(int(entry))

	def getPorts(self):
		ports = []
		for p in self.ports:
			ports.append(p)
		return ports

	def parseProto(self, proto):
		for entry in proto.split(','):
			entry = entry.lower()
			if entry == 'tcp':
				self.proto.add('tcp')
			elif entry == 'udp':
				self.proto.add('udp')
			else:
				print 'WARNING: Unknown protocol: %s' % entry

	def getProto(self):
		proto = []
		for p in self.proto:
			proto.append(p)
		return proto

# ICMP
# Performs an ICMP ping of the given host.
def icmp(host):
	result = sr1(IP(dst = host) / ICMP(type = 'echo-request'), timeout = 1, verbose = 0)
	return result != None

# TCP
# Performs a TCP SYN scan of the given host and port.
def tcp(host, port):
	result = sr1(IP(dst = host) / TCP(dport = port, flags = 'S'), timeout = 1, verbose = 0)
	if result != None:
		print '    %s TCP' % port
	return result != None

# UDP
# Performs a UDP scan of the given host and port.
# NOTE: This method is prone to false positives, since it assumes that no response indicates an open port.
def udp(host, port):
	result = sr1(IP(dst = host) / UDP(dport = port), timeout = 1, verbose = 0)
	if result == None:
		print '    %s UDP' % port
	return result == None

# Setup the protocol handler map.
protoHandlers = {}
protoHandlers['icmp'] = icmp
protoHandlers['tcp'] = tcp
protoHandlers['udp'] = udp

if __name__ == '__main__':

	# Setup the command line interface.
	parser = argparse.ArgumentParser()
	parser.add_argument('--hosts', action = 'store', default = None, type = str, help = 'A list of host ranges to scan.', metavar = 'HOSTS', dest = 'hosts')
	parser.add_argument('--hosts-file', action = 'store', default = None, type = str, help = 'A file containing lists of host ranges to scan.', metavar = 'HOSTS_FILE', dest = 'hosts_file')
	parser.add_argument('--ports', action = 'store', default = None, type = str, help = 'A list of port ranges to scan.', metavar = 'PORTS', dest = 'ports')
	parser.add_argument('--ports-file', action = 'store', default = None, type = str, help = 'A file containing lists of port ranges to scan.', metavar = 'PORTS_FILE', dest = 'ports_file')
	parser.add_argument('--ping', action = 'store_true', default = False, help = 'ICMP ping hosts before scanning ports.', dest = 'ping')
	parser.add_argument('--protocols', action = 'store', default = None, type = str, help = 'A list of protocols to use for scanning. Available protocols are TCP and UDP.', metavar = 'PROTOCOLS', dest = 'proto')
	parser.add_argument('--html', action = 'store', default = None, type = str, help = 'A location to output an HTML report of the scan.', metavar = 'HTML', dest = 'html')

	# Process the command line arguments.
	defaultHosts = '127.0.0.1'
	defaultPorts = '0-1023'
	defaultProto = 'tcp'
	args = parser.parse_args()
	targetParser = TargetParser()
	if (args.hosts):
		targetParser.parseHosts(args.hosts)
	if (args.hosts_file):
		hostsFile = open(args.hosts_file, 'r')
		for line in hostsFile.read().split('\n'):
			if len(line) > 0:
				targetParser.parseHosts(line)
		hostsFile.close()
	hosts = targetParser.getHosts()
	if len(hosts) < 1:
		print 'WARNING: No hosts were specified. Default hosts will be used.'
		targetParser.parseHosts(defaultHosts)
		hosts = targetParser.getHosts()
	print '%s unique hosts will be scanned.' % len(hosts)
	if (args.ports):
		targetParser.parsePorts(args.ports)
	if (args.ports_file):
		portsFile = open(args.ports_file, 'r')
		for line in portsFile.read().split('\n'):
			if len(line) > 0:
				targetParser.parsePorts(line)
		portsFile.close()
	ports = targetParser.getPorts()
	if len(ports) < 1:
		print 'WARNING: No ports were specified. Default ports will be used.'
		targetParser.parsePorts(defaultPorts)
		ports = targetParser.getPorts()
	print '%s unique ports will be scanned.' % len(ports)
	ping = args.ping
	if ping:
		print 'Hosts will receive ICMP ping before being scanned.'
	if (args.proto):
		targetParser.parseProto(args.proto)
	proto = targetParser.getProto()
	if len(proto) < 1:
		print 'WARNING: No protocols were specified. Default protocols will be used.'
		targetParser.parseProto(defaultProto)
		proto = targetParser.getProto()
	print 'The following %s protocols will be used: %s' % (len(proto), proto)
	if args.html:
		print 'An HTML report will be saved to the following location: "%s".' % args.html

	# Perform the scans.
	results = {}
	for host in hosts:
		hostStr = intToDottedDecimal(host)
		if not ping or protoHandlers['icmp'](hostStr):
			print '--------------------------------------------------------------------------------'
			print hostStr
			results[host] = {}
			for port in ports:
				for p in proto:
					result = protoHandlers[p](hostStr, port)
					if result:
						if port not in results[host]:
							results[host][port] = {}
						results[host][port][p] = result

	# Output HTML if requested.
	if args.html:
		htmlStr = '<html><head><title>Scan Report</title></head><body><center>'
		htmlStr += '<h1>Scan Report</h1>'
		for host in results:
			htmlStr += '<br><br><h3>%s</h3>' % intToDottedDecimal(host)
			if len(results[host]) < 1:
				htmlStr += '<br><i>No open ports found.</i>'
			else:
				htmlStr += '<br><table>'
				for port in results[host]:
					for p in results[host][port]:
						htmlStr += '<tr><td>%s</td><td>%s</td></tr>' % (port, p)
				htmlStr += '</table>'
		htmlStr += '</center></body></html>'
		htmlFile = open(args.html, 'w')
		htmlFile.write(htmlStr)
