from cobstix2 import *

def main():

  
  ind = Indicator(name='Something', labels=['malicious-activity'], pattern="file-object.hashes.md5 = '3773a88f65a5e780c8dff9dce3a056f3'")
  #ind.name = 'a new one'
  #tlp_red = ind.set_tlp('red', ['description', 'title'])

  #ind2 = Indicator(labels=['malicious-activity'], pattern="file-object.hashes.md5 = '3773a88f65a5e780c8dff9dce3a056f3'")
  #tlp_red = ind2.set_tlp('red')
  #mal = Malware(labels=['remote-access-trojan', 'screen-capture'], )

  #rel = Relationship('indicates', 'bundle--350893cc-95ea-4787-9dcf-52855ece21b9')
  #rel.set_text('something in desc')

  #iset = IntrusionSet(name='badguy', primary_motivation='accidental', secondary_motivations=['accidental', 'coercion'])

  #cam = Campaign(name='something', first_seen='2015-02-03T14:56:21.528000Z')
  #cam.set_aliases(['test', 'another'])

  all_sdo = get_all_SDO()

  """
  obj_refs = []
  for obj in all_sdo:
    obj_refs.append(obj.id)
  rep = Report()
  rep.set_object_refs(obj_refs)
  """

  bun = Bundle(objects=all_sdo)
  print bun

  

  #bun.add_object(cam)
  #print bun

  """
  response = query('marking-definition--597429af-b1a6-396e-a73b-a6adad0461a4')
  print response

  response = query('indicator--e8bd96f5-8bf4-4e41-9d59-3af6797821b3')
  print response
  """
  
  

if __name__ == '__main__':
  main()