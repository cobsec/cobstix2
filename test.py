from cobstix2 import *

def main():

  ind = Indicator(labels=['malicious-activity'], pattern="file-object.hashes.md5 = '3773a88f65a5e780c8dff9dcd3a056f3'")
  #tlp_red = ind.set_tlp('red', ['description', 'title'])

  ind2 = Indicator(labels=['malicious-activity'], pattern="file-object.hashes.md5 = '3773a88f65a5e780c8dff9dce3a056f3'")
  #tlp_red = ind.set_tlp('red')

  mal = Malware(labels=['remote-access-trojan', 'screen-capture'], )

  rel = Relationship('indicates', ind.id, mal.id)
  rel.set_text('something in desc')

  all_sdo = get_all_SDO()

  """
  obj_refs = []
  for obj in all_sdo:
    obj_refs.append(obj.id)
  rep = Report()
  rep.set_object_refs(obj_refs)
  """
  
  #print all_sdo
  bun = Bundle(objects=all_sdo)
  print bun

  cam = Campaign()
  cam.set_aliases(['test', 'another'])

  bun.add_object(cam)
  print bun

  """
  response = query('marking-definition--597429af-b1a6-396e-a73b-a6adad0461a4')
  print response

  response = query('indicator--e8bd96f5-8bf4-4e41-9d59-3af6797821b3')
  print response
  """
  
  

if __name__ == '__main__':
  main()