from common_tools import *
import sys
import json

class Cybox(object):
  def __init__(self, *args, **kwargs):
    self.description(kwargs.get('description', None))
    self.extensions(kwargs.get('extensions', None))

  def set_attribute(object, attribute, input, _type, vocab_ref=None, required=False):
    if input is not None:
      if vocab_ref == 'cybox-object-refs':
        if is_cybox_object_ref(object, input):
          setattr(object, attribute, input)
      elif is_valid(input, _type, vocab_ref):
        setattr(object, attribute, input)
    else:
      if required:
        err_required(object.type, attribute)

  def description(self, _description):
    self.set_attribute('description', _description, str)

  def extensions(self, _extensions):
    self.set_attribute('extensions', _extensions, dict, 'cybox-object')

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

class ASObject(Cybox):
  type = 'autonomous-system'
  def __init__(self, *args, **kwargs):
    self.type = ASObject.type
    super(ASObject, self).__init__(*args, **kwargs)
    self.number(kwargs.get('number', None))
    self.name(kwargs.get('name', None))
    self.rir(kwargs.get('rir', None))
  
  def number(self, _number):
    self.set_attribute('number', _number, int, None, True)

  def name(self, _name):
    self.set_attribute('name', _name, str)

  def rir(self, _rir):
    self.set_attribute('rir', _rir, str)

class IPv4Address(Cybox):
  type = 'ipv4-addr'
  def __init__(self, *args, **kwargs):
    self.type = IPv4Address.type
    super(IPv4Address, self).__init__(*args, **kwargs)
    self.value(kwargs.get('value', None))
    self.resolves_to_refs(kwargs.get('resolves_to_refs', None))
    self.belongs_to_refs(kwargs.get('belongs_to_refs', None))
  
  def value(self, _value):
    self.set_attribute('value', _value, str, None, True)

  def resolves_to_refs(self, _resolves_to_refs):
    self.set_attribute('resolves_to_refs', _resolves_to_refs, list, 'cybox-object-refs')

  def belongs_to_refs(self, _belongs_to_refs):
    self.set_attribute('resolves_to_refs', _belongs_to_refs, list, 'cybox-object-refs')

class NetworkTraffic(Cybox):
  type = 'network-traffic'
  def __init__(self, *args, **kwargs):
    self.type = NetworkTraffic.type
    super(NetworkTraffic, self).__init__(*args, **kwargs)
    self.start(kwargs.get('start', None))
    self.end(kwargs.get('end', None))
    self.is_active(kwargs.get('is_active', None))
    self.src_ref(kwargs.get('src_ref', None))
    self.dst_ref(kwargs.get('dst_ref', None))
    self.src_port(kwargs.get('src_port', None))
    self.dst_port(kwargs.get('dst_port', None))
    self.protocols(kwargs.get('protocols', None))
    self.src_byte_count(kwargs.get('src_byte_count', None))
    self.dst_byte_count(kwargs.get('dst_byte_count', None))
    self.src_packets(kwargs.get('src_packets', None))
    self.dst_packets(kwargs.get('dst_packets', None))
    self.ipfix(kwargs.get('ipfix', None))
    self.src_payload_ref(kwargs.get('src_payload_ref', None))
    self.dst_payload_ref(kwargs.get('dst_payload_ref', None))
    self.encapsulates_refs(kwargs.get('encapsulates_refs', None))
    self.encapsulated_by_ref(kwargs.get('encapsulated_by_ref', None))
  
  def start(self, _start):
    self.set_attribute('start', _start, str, 'timestamp')

  def end(self, _end):
    self.set_attribute('end', _end, str, 'timestamp')

  def is_active(self, _is_active):
    self.set_attribute('is_active', _is_active, bool)

  def src_ref(self, _src_ref):
    self.set_attribute('src_ref', _src_ref, str, 'cybox-object-refs')

  def dst_ref(self, _dst_ref):
    self.set_attribute('dst_ref', _dst_ref, str, 'cybox-object-refs')

  def src_port(self, _src_port):
    self.set_attribute('src_port', _src_port, int)

  def dst_port(self, _dst_port):
    self.set_attribute('dst_port', _dst_port, int)

  def protocols(self, _protocols):
    self.set_attribute('protocols', _protocols, list, None, True)

  def src_byte_count(self, _src_byte_count):
    self.set_attribute('src_byte_count', _src_byte_count, int)

  def dst_byte_count(self, _dst_byte_count):
    self.set_attribute('dst_byte_count', _dst_byte_count, int)

  def src_packets(self, _src_packets):
    self.set_attribute('src_packets', _src_packets, int)

  def dst_packets(self, _dst_packets):
    self.set_attribute('dst_packets', _dst_packets, int)

  def ipfix(self, _ipfix):
    self.set_attribute('ipfix', _ipfix, dict)

  def src_payload_ref(self, _src_payload_ref):
    self.set_attribute('src_payload_ref', _src_payload_ref, str, 'cybox-object-refs')

  def dst_payload_ref(self, _dst_payload_ref):
    self.set_attribute('dst_payload_ref', _dst_payload_ref, str, 'cybox-object-refs')

  def encapsulates_refs(self, _encapsulates_refs):
    self.set_attribute('encapsulates_refs', _encapsulates_refs, list, 'cybox-object-refs')

  def encapsulated_by_ref(self, _encapsulated_by_ref):
    self.set_attribute('encapsulated_by_ref', _encapsulated_by_ref, str, 'cybox-object-refs')

class Container(object):
  def __init__(self, *args, **kwargs):
    self.objects(kwargs.get('objects', None))

  def objects(self, _objects):
    if _objects is not None:
      _index = 0
      for _object in _objects:
        if type(_object) is dict:
          setattr(self, str(_index), _object)
        else:
          setattr(self, str(_index), _object.__dict__)
        _index += 1

  def build_with_refs(parent_object, attribute, _objects, close=False):
    if type(_objects) is not list:
      obj_list = [_objects]
    else:
      obj_list = _objects
    _index = 0
    refs = []
    for object in obj_list:
      refs.append(str(_index))
      _index += 1
    setattr(parent_object, attribute, refs)
    if close:
      obj_list.append(parent_object)
    container = Container(objects=obj_list)
    return container

  def add_object(self, _object):
    count = len(self.__dict__)
    setattr(self, str(count), _object.__dict__)
    return count

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

def create_network_traffic_object(protocols, src_ip, dst_ip):

  src_ip_obj = IPv4Address(value=src_ip)
  dst_ip_obj = IPv4Address(value=dst_ip)

  container = Container()
  src_ip_ref = container.add_object(src_ip_obj)
  dst_ip_ref = container.add_object(dst_ip_obj)
  net_traffic_obj = NetworkTraffic(protocols=protocols)
  net_traffic_obj.src_ref = src_ip_ref
  net_traffic_obj.dst_ref = dst_ip_ref
  count = container.add_object(net_traffic_obj)
  return container