from cobstix2 import *
from random import randint

def main():

  indicators = []
  ind_ids = []

  for i in range(20):
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

if __name__ == '__main__':
  main()