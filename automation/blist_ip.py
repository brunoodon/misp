from pymisp import MISPEvent, MISPObject, PyMISP, ExpandedPyMISP, MISPSharingGroup
import urllib
url_blist = "https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt"
misp_key = "ywQahrmstmir28pVmdLCGjV99PlJjCtlVOp8bUvZ"
misp_url = "https://192.168.1.50"
misp_verify_cert = False
blist = urllib.request.urlopen(url_blist)
#print(blist)
misp = ExpandedPyMISP(misp_url, misp_key, misp_verify_cert)
event = MISPEvent()
event.info = "Blocklisted IP"
event.distibution = "0"
event.analysis = "1"
event.threat_level_id = "1"
event.distribution = "2"
event.add_tag('tlp:green')
event.add_tag('osint:source-type="block-or-filter-list"')
for i in blist:  
    ip = str(i.decode("utf-8").replace('\n', ''))
#    print(ip)
    event.add_attribute('ip-dst', str(ip), comment="Blocklisted IP", disable_correlation=False, to_id=True)
event.published = True
event = misp.add_event(event)
