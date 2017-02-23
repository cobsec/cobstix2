from cobstix2 import *
from cobbox import *
from random import randint
import re

def main():
  
  #Create watchlist of random IPs (make one deterministic so simulate a response)
  indicators = []
  ind_ids = []

  ind = Indicator(name='[EXAMPLE] Malicious infrastructure IP address', description='[EXAMPLE] Fake, randomly generated indicator to demonstrate stix2 object composition for CTI Adapter sharing.', labels=['malicious-activity'], pattern="ipv4-addr:value = '1.3.3.7'")
  indicators.append(ind)
  ind_ids.append(ind.id)
  for i in range(4):
    ind = Indicator(name='[EXAMPLE] Malicious infrastructure IP address', description='[EXAMPLE] Fake, randomly generated indicator to demonstrate stix2 object composition for CTI Adapter sharing.', labels=['malicious-activity'], pattern="ipv4-addr:value = '" + str(randint(1,255)) + "." + str(randint(1,255)) + "." + str(randint(1,255)) + "." + str(randint(1,255)) + "'")
    indicators.append(ind)
    ind_ids.append(ind.id)
  rep = Report(name='[EXAMPLE] Indicator watchlist for CTI Log Adapter', labels=['threat-report'], object_refs=ind_ids)
  coa = CourseOfAction(name='[EXAMPLE] CTI Adapter - VERIFY', description='[EXAMPLE] Report objects related-to this CoA are candidates for CTI Adapter sharing')
  rel_rep_coa = Relationship('related-to', rep.id, coa.id)
  indicators.append(rep)
  indicators.append(coa)
  indicators.append(rel_rep_coa)

  bun = Bundle(objects=indicators)
  with open('watchlist.json', 'wb') as f:
    f.write(str(bun))


  #Create a response bundle containing null sightings for all but the deterministic one
  obj = file_to_obj('watchlist.json')

  if obj.type == 'bundle':
    for _dict in obj.objects:
      object = dict_to_obj(_dict)
      if object.type == 'report':
        ind_list = object.object_refs

  #obtain test_string (observed IP activity) and test_time (timestamp of observed activity) from log file, or whatever!
  test_src = '1.3.3.7'
  test_dst = '8.0.4.7'
  test_time = '2017-01-18T08:13:43.565000Z'
  test_protos = ['tcp','ipv4','http']
  sightings = []
  for _dict in obj.objects:
    object = dict_to_obj(_dict)
    try:
      ip_pattern = re.sub("'", '', object.pattern.split(' = ')[1])
      sighting = Sighting(name='CTI Adapter Sighting Response', sighting_of_ref=object.id)
      if ip_pattern == test_src:
        sighting.count = 1
        sighting.first_seen = test_time
      else:
        sighting.count = 0
      sightings.append(sighting)
    except AttributeError:
      pass

  bun = Bundle(objects=sightings)
  with open('binary_response.json', 'wb') as f:
    f.write(str(bun))

  #Same again, but this time with a network traffic cybox object
  sightings = []
  for _dict in obj.objects:
    object = dict_to_obj(_dict)
    try:
      ip_pattern = re.sub("'", '', object.pattern.split(' = ')[1])
      sighting = Sighting(name='CTI Adapter Sighting Response', sighting_of_ref=object.id)
      if ip_pattern == test_src:
        sighting.count = 1
        sighting.first_seen = test_time
        net_traff_dict = create_network_traffic_object(test_protos, test_src, test_dst).__dict__
        obs_data = ObservedData(name='CTI Adapter log entry data', first_observed=test_time, number_observed=1, objects=net_traff_dict)
        sighting.observed_data_refs = [obs_data.id]
        sightings.append(obs_data)
      else:
        sighting.count = 0
      sightings.append(sighting)
    except AttributeError:
      pass

  bun = Bundle(objects=sightings)
  with open('cybox_response.json', 'wb') as f:
    f.write(str(bun))

  

if __name__ == '__main__':
  main()