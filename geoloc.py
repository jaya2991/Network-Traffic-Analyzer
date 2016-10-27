from geoip import geolite2
#import win_inet_pton
import dpkt
import socket
import netifaces as ni
import optparse

def retGeoStr(ip):
	try:
		myIP = ni.ifaddresses('wlan0')[2][0]['addr']
		if ip == myIP:
			geoLoc = "My Location"
			return geoLoc
		else:
			match = geolite2.lookup(ip)
			city = match.timezone
			country = match.country
			continent = match.continent
			if city == 'None':
				geoLoc = country 
			else:
				geoLoc = city + ', ' + country + ', ' + continent
			return geoLoc
	except Exception, e:
		return 'Unregistered'

def printPcap(pcap):
	try:
		for p in pcap:
			try:
				(ts, buf) = p
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
				src = socket.inet_ntoa(ip.src)
				dst = socket.inet_ntoa(ip.dst)
				print '[+] Src: ' + src + ' --> Dst: ' + dst
				print '[+] Src: ' + retGeoStr(src) + ' --> Dst: ' \
				+ retGeoStr(dst)
			except Exception, e:
				pass
	except Exception, e:
		pass 
			
			
def main():
	parser = optparse.OptionParser('usage%prog -p <pcap file>')
	parser.add_option('-p', dest='pcapFile', type='string',\
	help='specify pcap filename')
	(options, args) = parser.parse_args()
	if options.pcapFile == None:
		print parser.usage
		exit(0)
	pcapFile = options.pcapFile
	f = open(pcapFile)
	pcap = dpkt.pcap.Reader(f)
	printPcap(pcap)
if __name__ == '__main__':
	main()

