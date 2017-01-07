from cobstix2 import *

def main():

  ind = Indicator()
  ind.set_labels(['malicious-activity'])
  ind.set_text('Derp Malware', 'This file is part of Derp')
  ind.set_pattern("file-object.hashes.md5 = '3773a88f65a5e780c8dff9dcd3a056f3'", 'cybox')
  #tlp_red = ind.set_tlp('red')

  ind2 = Indicator()
  ind2.set_labels(['malicious-activity'])
  ind2.set_text('Derp Malware', 'This file is part of Derp')
  ind2.set_pattern("file-object.hashes.md5 = '3773a88f65a5e780c8dff9dce3a056f3'", 'cybox')
  #tlp_red = ind.set_tlp('red')

  mal = Malware()
  mal.set_labels(['remote-access-trojan', 'screen-capture', 'spyware'])
  mal.set_text('Derp', 'Open source malware')
  mal.set_kill_chain_phase('lm', 'firstphase')

  rel = Relationship('indicates', ind.id, mal.id)
  rel.set_text('something in desc')

  cam = Campaign()
  cam.set_aliases(['test', 'another'])

  all_sdo = get_all_SDO()
  bun = bundle(*all_sdo)

  rep = Report()
  rep.set_object_refs(['marking-definition--597429af-b1a6-396e-a73b-a6adad0461a4', 'indicator--e8bd96f5-8bf4-4e41-9d59-3af6797821b3'])

  print mal

  #print bun
  """
  response = query_by_ref('elk', 'marking-definition--597429af-b1a6-396e-a73b-a6adad0461a4')
  print response

  response = query_by_ref('elk', 'indicator--e8bd96f5-8bf4-4e41-9d59-3af6797821b3')
  print response
  """
  
  

if __name__ == '__main__':
  main()