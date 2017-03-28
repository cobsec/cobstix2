from __future__ import print_function
from cobstix2 import *
#from stix2 import *
from stixelk import put_elk
import datetime
import csv
from IPy import IP

from stix2validator import validate_file, print_results

ENRICH = False

try:
  #Try importing a local 'enrich' library
  from enrich import *
  ENRICH = True
except ImportError:
  pass

default_tlp = TLPMarking(definition={'tlp' : 'white'})
default_creator = Identity(name='nccic', identity_class='organization')
vt_ident = Identity(name='virustotal', identity_class='organization')

def apply_vt(object):
  object.set_created_by_ref(name=vt_ident.name, identity_class=vt_ident.identity_class)
  object.set_tlp(definition=default_tlp.definition)
  object.set_text('GRIZZLY STEPPE VT Enrichment', 'Object identified from enrichment against VirusTotal')

def main():

  gs_cam = Campaign(name='GRIZZLY STEPPE', created_by_ref=default_creator.id, object_marking_refs=[default_tlp.id], first_seen=datetime.datetime(2015, 6, 1, 0, 0, 0).isoformat('T') + 'Z', description='Cyber-enabled operations alleged by US Government to originate from Russian activity against US Political targets')

  # Attribution Objects and linkages (pivoting off Campaign)
  ris_ta = ThreatActor(name='RIS', description='Russian civilian and military intelligence Services (RIS)', created_by_ref=default_creator.id, object_marking_refs=[default_tlp.id], labels=['nation-state'])

  apt28_is = IntrusionSet(name='APT28', created_by_ref=default_creator.id, object_marking_refs=[default_tlp.id])
  apt29_is = IntrusionSet(name='APT29', created_by_ref=default_creator.id, object_marking_refs=[default_tlp.id])

  apt28_ris_rel = Relationship(relationship_type='attributed-to', source_ref=apt28_is.id, target_ref=ris_ta.id)
  apt29_ris_rel = Relationship(relationship_type='attributed-to', source_ref=apt29_is.id, target_ref=ris_ta.id)
  gs_apt28_rel = Relationship(relationship_type='attributed-to', source_ref=gs_cam.id, target_ref=apt28_is.id)
  gs_apt29_rel = Relationship(relationship_type='attributed-to', source_ref=gs_cam.id, target_ref=apt29_is.id)

  attribution = [gs_cam, ris_ta, apt28_is, apt29_is, apt28_ris_rel, apt29_ris_rel, gs_apt28_rel, gs_apt29_rel]

  data = []
  with open('test.csv', 'rb') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
      if row[0] is not '' and row[1] is not '':
        data.append([row[0], row[1]])

  list_length = len(data)
  uri_inds = [[] for j in range(list_length)]
  ip_inds = [[] for j in range(list_length)]
  mal_inds = [[] for j in range(list_length)]
  for i in range(list_length):
    is_file = False
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
      is_file = True
      pattern_type = "file:hashes.MD5"

      if ENRICH:
        vt_results = get_behavior_VT(pattern_value)
        if vt_results:
          for netloc in vt_results['netlocs']:
            uri_ind = Indicator(name='GRIZZLY STEPPE URI', created_by_ref=vt_ident.id, object_marking_refs=[default_tlp.id], labels=['malicious-activity'], pattern="[domain-name:value = '%s']" % str(netloc))
            uri_inds[i].append(uri_ind)
          for ip in vt_results['ips']:
            ip_ind = Indicator(name='GRIZZLY STEPPE IP', created_by_ref=vt_ident.id, object_marking_refs=[default_tlp.id], labels=['malicious-activity'], pattern="[ipv4-addr:value = '%s']" % str(ip))
            ip_inds[i].append(ip_ind)

    if pattern_type is not None:
      ind = Indicator(name='GRIZZLY STEPPE', created_by_ref=default_creator.id, object_marking_refs=[default_tlp.id], description=desc, labels=['malicious-activity'], pattern="[%s = '%s']" % (pattern_type, pattern_value))
      data[i].append(ind)
      
      if uri_inds[i] or ip_inds[i]:
        gs_mal = Malware(name='OnionDuke', created_by_ref=default_creator.id, object_marking_refs=[default_tlp.id], description='Malware identified as OnionDuke C2 software', labels=['remote-access-trojan'])
        data[i].append(gs_mal)
        cam_mal_rel = Relationship(relationship_type='uses', source_ref=gs_cam.id, target_ref=gs_mal.id)
        data[i].append(cam_mal_rel)
        ind_mal_rel = Relationship(relationship_type='indicates', source_ref=ind.id, target_ref=gs_mal.id)
        data[i].append(ind_mal_rel)
        if uri_inds[i]:
          for uri in uri_inds[i]:
            uri_malind_rel = Relationship(relationship_type='indicates', source_ref=uri.id, target_ref=gs_mal.id)
            data[i].append(uri_malind_rel)

        if ip_inds[i]:
          for ip in ip_inds[i]:
            ip_malind_rel = Relationship(relationship_type='indicates', source_ref=ip.id, target_ref=gs_mal.id)
            data[i].append(ip_malind_rel)
      else:
        ind_cam_rel = Relationship(relationship_type='indicates', source_ref=ind.id, target_ref=gs_cam.id)
        data[i].append(ind_cam_rel)
        
  all_sdo = get_all_SDO()
  orig_report = []
  enrich_inds = []
  ind_cam_rels = []
  relationships = []
  malwarez = []

  for sdo in all_sdo:
    if sdo.type == 'indicator':
      # Just the report
      if sdo.name == 'GRIZZLY STEPPE':
        orig_report.append(sdo)
      else:
        # Extra stuff from enrichment (if any)
        enrich_inds.append(sdo)

    # All of the other stuff I added!
    if sdo.type == 'relationship':
      relationships.append(sdo)
      if sdo.target_ref == gs_cam.id:
        ind_cam_rels.append(sdo)
    if sdo.type == 'malware':
      malwarez.append(sdo)

  bun_ind = Bundle(objects=orig_report)

  attr_context = orig_report + attribution + ind_cam_rels
  bun_attr = Bundle(objects=attr_context)

  full_context = attr_context + malwarez + enrich_inds + relationships
  bun_full = Bundle(objects=full_context)

  trusted = attribution + malwarez + enrich_inds + relationships
  bun_trust = Bundle(objects=trusted)

  with open('./out/1_orig_report.json', 'wb') as f:
    f.write(str(bun_ind))

  with open('./out/2_with_attribution.json', 'wb') as f:
    f.write(str(bun_attr))

  with open('./out/3_all_enriched.json', 'wb') as f:
    f.write(str(bun_full))

  with open('./out/4_trusted.json', 'wb') as f:
    f.write(str(bun_trust))

  results = validate_file('./out/1_orig_report.json')
  print_results(results)

  results = validate_file('./out/2_with_attribution.json')
  print_results(results)

  results = validate_file('./out/3_all_enriched.json')
  print_results(results)

  results = validate_file('./out/4_trusted.json')
  print_results(results)
  
  results = put_elk(*trusted)
  #print(results)


if __name__ == '__main__':
  main()