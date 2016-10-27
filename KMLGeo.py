from geoip import geolite2
#import win_inet_pton
import dpkt
import socket
import netifaces as ni
import optparse
import urllib
import simplejson

googleGeocodeUrl = 'http://maps.googleapis.com/maps/api/geocode/json?'
#MY_ADDRESS = '1063, Morse Ave, Sunnyvale, CA 94089'
MY_ADDRESS = 'San Jose State University'
MY_LOCATION = ''

def get_coordinates(query, from_sensor=False):
    query = query.encode('utf-8')
    params = {
        'address': query,
        'sensor': "true" if from_sensor else "false"
    }
    url = googleGeocodeUrl + urllib.urlencode(params)
    json_response = urllib.urlopen(url)
    response = simplejson.loads(json_response.read())
    if response['results']:
        location = response['results'][0]['geometry']['location']
        latitude, longitude = location['lat'], location['lng']
        #print query, latitude, longitude
    else:
        latitude, longitude = None, None
        #print query, "<no results>"
    return latitude, longitude

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

def retKML(ip):
	try:
		kml = ''
		if ip == ni.ifaddresses('wlan0')[2][0]['addr']:
			if MY_LOCATION == '':
				MY_LOCATION = get_coordinates(MY_ADDRESS)
			location = MY_LOCATION
			kml = (
				'<Placemark>\n'
				'<name>%s,%s</name>\n'
				'<Point>\n'
				'<coordinates>%6f,%6f</coordinates>\n'
				'</Point>\n'
				'</Placemark>\n'
				)%(ip, MY_ADDRESS, location[1], location[0])
		else:
			match = geolite2.lookup(ip)
			country = match.country
			timezone = match.timezone
			subdivision = match.subdivisions
			location = match.location
			#print location
			kml = (
				'<Placemark>\n'
				'<name>%s,%s,%s</name>\n'
				'<Point>\n'
				'<coordinates>%6f,%6f</coordinates>\n'
				'</Point>\n'
				'</Placemark>\n'
				)%(ip, timezone, country, location[1], location[0])
		return kml
	except Exception, e:
		return ''

def getLocation(ip):
	try:
		if ip == ni.ifaddresses('wlan0')[2][0]['addr']:
			#if MY_LOCATION == '':
			#	MY_LOCATION = get_coordinates(MY_ADDRESS)
			#location = MY_LOCATION
			location = get_coordinates(MY_ADDRESS)
			return '', MY_ADDRESS, location
		else:
			match = geolite2.lookup(ip)
			country = match.country
			timezone = match.timezone
			subdivision = match.subdivisions
			location = match.location
			return timezone, country, location
	except Exception, e:
		#print 'getLocation' + str(e)
		return ''

def retLineKML(srcIP, destIP):
	try:
		kml = ''
		srcTimezone, srcCountry, srcLocation = getLocation(srcIP)
		destTimezone, destCountry, destLocation = getLocation(destIP)
		kml = (
			'<Placemark>\n'
			'<name>%s,%s,%s</name>\n'
			'<Point>\n'
			'<coordinates>%6f,%6f</coordinates>\n'
			'</Point>\n'
			'</Placemark>\n'
			'<Placemark>\n'
			'<name>%s,%s,%s</name>\n'
			'<Point>\n'
			'<coordinates>%6f,%6f</coordinates>\n'
			'</Point>\n'
			'</Placemark>\n'
			'<Placemark>\n'
			'<LineString>\n'
			'<color>#ff0000</color>\n'
			'<coordinates>\n'
			'%6f, %6f, 0.\n' 
			'%6f, %6f, 0.\n'
			'</coordinates>\n'
			'</LineString>\n'
			'</Placemark>\n'
		)%(srcIP, srcTimezone, srcCountry, srcLocation[1], srcLocation[0], destIP, destTimezone, destCountry, destLocation[1], destLocation[0], srcLocation[1], srcLocation[0], destLocation[1], destLocation[0])
		return kml
	except Exception, e:
		#print str(e)
		return ''

def printPcap(pcap):
	kmlpts = ''
	try:
		for p in pcap:
			try:
				(ts, buf) = p
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
				src = socket.inet_ntoa(ip.src)
				#srcKML = retKML(src)
				dst = socket.inet_ntoa(ip.dst)
				#dstKML = retKML(dst)
				#print '[+] Src: ' + src + ' --> Dst: ' + dst
				#print '[+] Src: ' + retGeoStr(src) + ' --> Dst: ' \
				#+ retGeoStr(dst)
				#kmlpts = kmlpts + srcKML + dstKML
				kmlpts = kmlpts + retLineKML(src, dst)
			except Exception, e:
				pass
		return kmlpts
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
	#printPcap(pcap)
	kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\
	\n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'
	kmlfooter = '</Document>\n</kml>\n'
	kmldoc=kmlheader+printPcap(pcap)+kmlfooter
	print kmldoc

if __name__ == '__main__':
	main()

