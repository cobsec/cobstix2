from __future__ import print_function
from cobstix2 import *
import datetime
import csv
from IPy import IP

ENRICH = False
try:
  #Try importing a local 'enrich' library
  from enrich import *
  ENRICH = True
except ImportError:
  pass

default_tlp = TLPMarking(definition='white')
default_creator = Identity(name='nccic', identity_class='organisation')
vt_ident = Identity(name='virustotal', identity_class='organisation')

def apply_defaults(object):
  object.set_created_by_ref(name=default_creator.name, identity_class=default_creator.identity_class)
  object.set_tlp(definition=default_tlp.definition)

def apply_vt(object):
  object.set_created_by_ref(name=vt_ident.name, identity_class=vt_ident.identity_class)
  object.set_tlp(definition=default_tlp.definition)
  object.set_text('GRIZZLY STEPPE VT Enrichment', 'Object identified from enrichment against VirusTotal')

def main():

  gs_cam = Campaign()
  apply_defaults(gs_cam)
  first_seen = datetime.datetime(2015, 6, 1, 0, 0, 0).isoformat('T') + 'Z'
  gs_cam.set_first_seen(first_seen, 'month')
  gs_cam.set_text('GRIZZLY STEPPE', 'Cyber-enabled operations alleged by US Government to originate from Russian activity against US Political targets')
  

  ris_ta = ThreatActor()
  apply_defaults(ris_ta)
  ris_ta.set_text('RIS', 'Russian civilian and military intelligence Services (RIS)')

  apt28_is = IntrusionSet()
  apply_defaults(apt28_is)
  apt28_is.set_text('APT28')

  apt29_is = IntrusionSet()
  apply_defaults(apt29_is)
  apt29_is.set_text('APT29')

  apt28_ris_rel = Relationship('attributed-to', apt28_is.id, ris_ta.id)
  apply_defaults(apt28_ris_rel)
  apt29_ris_rel = Relationship('attributed-to', apt29_is.id, ris_ta.id)
  apply_defaults(apt29_ris_rel)
  gs_apt28_rel = Relationship('attributed-to', gs_cam.id, apt28_is.id)
  apply_defaults(gs_apt28_rel)
  gs_apt29_rel = Relationship('attributed-to', gs_cam.id, apt29_is.id)
  apply_defaults(gs_apt29_rel)

  data = []
  with open('test.csv', 'rb') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
      if row[0] is not '' and row[1] is not '':
        data.append([row[0], row[1]])

  list_length = len(data)
  uri_inds = [[] for j in range(list_length)]
  ip_inds = [[] for j in range(list_length)]
  for i in range(list_length):
    pattern_type = None
    pattern_value = data[i][0]
    desc = 'Suspected GRIZZLY STEPPE comms'
    if data[i][1] == 'IPV4ADDR':
      pattern_type = "ipv4-addr:value"
    elif data[i][1] == 'FQDN':
      pattern_type = "domain-name:value"
    elif data[i][1] == 'URL':
      pattern_type = "url:value"
    elif data[i][1] == 'MD5':
      pattern_type = "file-object.hashes.md5"
      desc = 'Suspected GRIZZLY STEPPE malware'
      gs_mal = Malware()
      gs_mal.set_labels(['remote-access-trojan'])
      gs_mal.set_text('OnionDuke', 'Malware identified as OnionDuke C2 software')
      apply_defaults(gs_mal)
      data[i].append(gs_mal)
      cam_mal_rel = Relationship('uses', gs_cam.id, gs_mal.id)
      apply_defaults(cam_mal_rel)
      data[i].append(cam_mal_rel)
      if ENRICH:
        vt_results = get_behavior_VT(pattern_value)
        if vt_results:
          for netloc in vt_results['netlocs']:
            uri_ind = Indicator(labels='malicious-activity', pattern="domain-name:value = '%s'" % netloc)
            apply_vt(uri_ind)
            uri_inds[i].append(uri_ind)
          for ip in vt_results['ips']:
            ip_ind = Indicator(labels='malicious-activity', pattern="ipv4-addr:value = '%s'" % ip)
            apply_vt(ip_ind)
            ip_inds[i].append(ip_ind)

    if pattern_type is not None:
      ind = Indicator(labels='malicious-activity', pattern="%s = '%s'" % (pattern_type, pattern_value))
      ind.set_text('GRIZZLY STEPPE', desc)
      apply_defaults(ind)

      ind_cam_rel = Relationship('indicates', ind.id, gs_cam.id)
      apply_defaults(ind_cam_rel)
      data[i].append(ind)
      data[i].append(ind_cam_rel)

      if uri_inds[i]:
        for uri in uri_inds[i]:
          uri_malind_rel = Relationship('indicates', uri.id, gs_mal.id)
          apply_defaults(uri_malind_rel)
          data[i].append(uri_malind_rel)

      if ip_inds[i]:
        for ip in ip_inds[i]:
          ip_malind_rel = Relationship('indicates', ip.id, gs_mal.id)
          apply_defaults(ip_malind_rel)
          data[i].append(ip_malind_rel)
        
  all_sdo = get_all_SDO()
  bun = bundle(*all_sdo)
  print(bun)

  #results = put_elk(*all_sdo)
  #print(results)


  #out_file = open('out.json', 'w')
  #print(bun, file=out_file)
  #out_file.close()


if __name__ == '__main__':
  main()