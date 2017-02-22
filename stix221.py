import re

from common_tools import *
from cobstix2 import *

from stix.core import STIXPackage, CourseOfAction, Indicator
from cybox.core import Observables, Observable
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from stix.utils import idgen


def main():
  NAMESPACE = {"https://www.ncsc.gov.uk/": "ncscuk"}
  idgen.set_id_namespace(NAMESPACE)
  pkg = STIXPackage()
  coa = CourseOfAction()

  obj = file_to_obj('out.json')
  if obj.type == 'bundle':
    for _dict in obj.objects:
      object = dict_to_obj(_dict)
      if object.type == 'indicator':
        ind = Indicator()
        id_str = object.id.replace('--', '-')
        print id_str
        #ind.id_ = object.id
        pattern_type = object.pattern.split(':')[0]
        _value = re.sub("'", '', object.pattern.split(' = ')[1])
        if pattern_type == 'ipv4-addr':
          obs = Observable(Address(address_value=_value, category=Address.CAT_IPV4))
        elif pattern_type == 'url':
          obs = Observable(URI(value=_value, type_=URI.TYPE_URL))
        pkg.add_observable(obs)
        obs_ref = Observable()
        obs_ref.id_ = None
        obs_ref.idref = obs.id_
        ind.add_observable(obs_ref)

  pkg.add_indicator(ind)
  print pkg.to_xml()

if __name__ == '__main__':
  main()