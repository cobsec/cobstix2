from cobstix2 import *
from random import randint

def main():

  indicators = []
  ind_ids = []

  for i in range(20):
    ind = Indicator(name='[EXAMPLE] Malicious infrastructure IP address', description='[EXAMPLE] Fake indicator generated to demonstrate stix2 object composition for CTI Adapter sharing.', labels=['malicious-activity'], pattern="ipv4-addr:value = '" + str(randint(1,255)) + "." + str(randint(1,255)) + "." + str(randint(1,255)) + "." + str(randint(1,255)) + "'")
    indicators.append(ind)
    ind_ids.append(ind.id)
  rep = Report(name='[EXAMPLE] Indicator watchlist for CTI Log Adapter', object_refs=ind_ids)
  indicators.append(rep)

  bun = Bundle(objects=indicators)
  print bun

if __name__ == '__main__':
  main()