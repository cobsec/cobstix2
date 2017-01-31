import sys
import json
from uuid import uuid4, uuid3, NAMESPACE_URL
from hashlib import sha1
import datetime
from pprint import pprint
import gc
import requests
import inspect

from vocab import *
from config import settings

USER = settings('stix')['created_by_string']
ELK = settings('kb_elk')['kb_ip']

def ns_uuid(_type, _string):
  return str(_type) + '--' + str(uuid3(NAMESPACE_URL, _string))

def uuid(_type):
  return str(_type) + '--' + str(uuid4())

class SDO(object):
  def __init__(self, *args, **kwargs):
    self.created = kwargs.get('created', datetime.datetime.utcnow().isoformat('T') + 'Z')
    self.modified = kwargs.get('modified', self.created)
    self.version = kwargs.get('version', '1')
    self.id = kwargs.get('id', uuid(self.type))
    self.created_by_ref = kwargs.get('created_by_ref', ns_uuid('identity', USER))
    self.set_labels(kwargs.get('labels', None))
    if 'name' in kwargs or 'description' in kwargs:
      self.set_text(kwargs.get('name', None), kwargs.get('description', None))

  def set_text(self, name=None, description=None):
    if name is not None:
      self.name = name
    if description is not None:
      self.description = description

  def set_labels(self, labels):
    if type(labels) is str:
      labels = [labels]

    if type(labels) is list and set(labels).issubset(OPEN_VOCAB['label'][self.type]):
      self.labels = labels
    elif labels is None:
      if self.type in OPEN_VOCAB:
        raise ValueError('[cobstix2] {labels} is not a valid {object} label (required)'.format(labels=repr(labels), object=repr(self.type)))
    else:
      raise ValueError('[cobstix2] {labels} is not a valid {object} label vocab'.format(labels=repr(labels), object=repr(self.type)))
    

  def set_tlp(self, definition, selectors=None):
    try:
      del self.object_marking_refs
    except AttributeError:
      pass
    try:
      del self.granular_markings
    except AttributeError:
      pass
    tlp_id = ns_uuid('marking-definition', definition)
    _tlp = query(tlp_id)
    if _tlp is False:
      _tlp = TLPMarking(definition=definition, id=tlp_id)
    if selectors is None:
      self.object_marking_refs = [tlp_id]
    else:
      self.granular_markings = [{'marking_ref': tlp_id, 'selectors': selectors}]
    return _tlp

  def set_created_by_ref(self, name, identity_class):
    id_ref = ns_uuid('identity', name)
    _identity = query(id_ref)
    if _identity is False:
      _identity = Identity(name=name, identity_class=identity_class, id=id_ref)
    else:
      self.created_by_ref = _identity[0].id
    return _identity

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

class Campaign(SDO):
  type = 'campaign'
  def __init__(self, *args, **kwargs):
    self.type = Campaign.type
    super(Campaign, self).__init__(*args, **kwargs)

  def set_aliases(self, aliases=None):
    self.aliases = []
    if type(aliases) is list:
      self.aliases = aliases
    else:
      self.aliases.append(aliases)

  def set_first_seen(self, first_seen=None, precision=None):
    if first_seen is None:
      self.first_seen = self.created
    else:
      self.first_seen = first_seen
      if precision is not None:
        self.first_seen_precision = precision

  def set_objective(self, objective=None):
    self.objective = objective

class CourseOfAction(SDO):
  type = 'course-of-action'
  def __init__(self, *args, **kwargs):
    self.type = CourseOfAction.type
    super(CourseOfAction, self).__init__(*args, **kwargs)

class Identity(SDO):
  type = 'identity'
  def __init__(self, *args, **kwargs):
    self.type = Identity.type
    super(Identity, self).__init__(*args, **kwargs)
    self.identity_class = kwargs.get('identity_class')
    

class Indicator(SDO):
  type = 'indicator'
  def __init__(self, *args, **kwargs):
    self.type = Indicator.type
    self.set_pattern(kwargs.get('pattern', None))
    super(Indicator, self).__init__(*args, **kwargs)
    self.set_labels
    self.valid_from = kwargs.get('valid_from', self.created)
    if 'valid_until' in kwargs:
      self.set_valid_until(kwargs.get('valid_until'))

  def set_pattern(self, pattern):
    if pattern:
      self.pattern = pattern
    else:
      raise ValueError('[cobstix2] {pattern} is not a valid Indicator pattern (required)'.format(pattern=repr(pattern)))

  def set_valid_until(self, valid_until):
    self.valid_until = valid_until

  def set_kill_chain_phase(self, kill_chain_name, phase_name):
    self.kill_chain_name = kill_chain_name
    self.phase_name = phase_name

#STUB
class IntrusionSet(SDO):
  type = 'intrusion-set'
  def __init__(self, *args, **kwargs):
    self.type = IntrusionSet.type
    super(IntrusionSet, self).__init__(*args, **kwargs)

class Malware(SDO):
  type = 'malware'
  def __init__(self, *args, **kwargs):
    self.type = Malware.type
    super(Malware, self).__init__(*args, **kwargs)
    if 'kill_chain_phases' in kwargs:
      self.kill_chain_phases = kwargs.get('kill_chain_phases')

  def set_kill_chain_phase(self, kill_chain_name, phase_name):
    self.kill_chain_phases = [{"kill_chain_name": kill_chain_name, "phase_name": phase_name}]
    
class Report(SDO):
  type = 'report'
  def __init__(self, *args, **kwargs):
    self.type = Report.type
    super(Report, self).__init__(*args, **kwargs)
    self.published = kwargs.get('published', datetime.datetime.utcnow().isoformat('T') + 'Z')
    
  def set_object_refs(self, object_refs):
    self.object_refs = []
    if type(object_refs) is list:
      self.object_refs = object_refs
    else:
      self.object_refs.append(object_refs)

#STUB
class ThreatActor(SDO):
  type = 'threat-actor'
  def __init__(self, *args, **kwargs):
    self.type = ThreatActor.type
    super(ThreatActor, self).__init__(*args, **kwargs)

class Tool(SDO):
  type = 'tool'
  def __init__(self, *args, **kwargs):
    self.type = Tool.type
    super(Tool, self).__init__(*args, **kwargs)

  def set_kill_chain_phase(self, kill_chain_name, phase_name):
    self.kill_chain_phases = [{"kill_chain_name": kill_chain_name, "phase_name": phase_name}]

  def set_tool_version(self, tool_version):
    self.tool_version = tool_version

class Relationship(SDO):
  type = 'relationship'
  def __init__(self, *args, **kwargs):
    self.type = Relationship.type
    super(Relationship, self).__init__(*args, **kwargs)
    if 'relationship_type' in kwargs:
      self.relationship_type = kwargs.get('relationship_type')
    else:
      self.relationship_type = args[0]

    if 'source_ref' in kwargs:
      self.source_ref = kwargs.get('source-ref')
    else:
      self.source_ref = args[1]

    if 'target_ref' in kwargs:
      self.target_ref = kwargs.get('target_ref')
    else:
      self.target_ref = args[2]

  def set_text(self, description):
    self.description = description

class Sighting(SDO):
  type = 'sighting'
  def __init__(self, *args, **kwargs):
    self.type = Sighting.type
    super(Sighting, self).__init__(*args, **kwargs)
    if 'sighting_of_ref' in kwargs:
      self.sighting_of_ref = kwargs.get('sighting_of_ref')
    else:
      self.sighting_of_ref = args[0]

class DataMarking(SDO):
  type = 'marking-definition'
  def __init__(self, *args, **kwargs):
    self.type = DataMarking.type
    super(DataMarking, self).__init__(*args, **kwargs)

class TLPMarking(DataMarking):
  definition_type = 'tlp'
  def __init__(self, *args, **kwargs):
    self.definition_type = TLPMarking.definition_type
    super(TLPMarking, self).__init__(*args, **kwargs)
    self.definition = kwargs.get('definition')

class Bundle():
  type = 'bundle'
  def __init__(self, *args, **kwargs):
    self.type = Bundle.type
    self.id = uuid(self.type)
    self.spec_version = '2.0'
    self.set_objects(kwargs.get('objects', None))

  def set_objects(self, objects):
    if type(objects) is list:
      self.objects = objects
    else:
      raise ValueError('[cobstix2] {objects} is not a valid object list to be Bundled (required)'.format(objects=repr(objects)))

  def add_object(self, object):
    if isinstance(object, SDO):
      self.objects.append(object.__dict__)

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

def get_all_SDO():
  SDO_list = []
  for obj in gc.get_objects():
    if isinstance(obj, SDO):
      SDO_list.append(obj.__dict__)
  return SDO_list

def dict_to_obj(_dict):
  #Use on incoming stix render as appropriate Class object (using this library)
  #Note: If attributes of incoming objects are not supported by this library, they won't be rendered
  if 'definition_type' in _dict:
    match_string = 'definition_type'
  else:
    match_string = 'type'

  for name, obj in inspect.getmembers(sys.modules[__name__]):
    if inspect.isclass(obj):
      try:
        #Special case to catch definition-type of marking-definition objects (which are the only effective 'nested' types in the spec...for some reason)
        if getattr(obj, match_string) == _dict[match_string]:
          return obj(**_dict)
      except AttributeError:
        pass
  return None

def query(value):
  try:
    query_type = settings('kb')['kb_type']
  except KeyError:
    print "[cobstix2] Could not read kb_type from kb settings in config.ini"
    sys.exit(0)

  if query_type == 'elk':
    _index = USER
    endpoint = ELK + '%s/_search' % _index
    payload = '{"query":{"query_string":{"query": "%s"}}}' % value
    try:
      r = requests.post(endpoint, payload)
      json_content = r.json()
    except requests.exceptions.RequestException as e:
      print e
      return False
    try:
      hit_list = json_content['hits']['hits']
      obj_list = []
      for hit in hit_list:
        new_obj = dict_to_obj(hit["_source"])
        obj_list.append(new_obj)
      return obj_list
    except KeyError:
      return False
  else:
    return False

def put_elk(*_payloads):
  results = []
  for _payload in _payloads:
    #print _payload
    if isinstance(_payload, SDO) or isinstance(_payload, Bundle):
      _index = USER
      _type = _payload.type
      _id = _payload.id.split('--')[1]
    else:
      return None
    endpoint = ELK + '%s/%s/%s' % (_index, _type, _id)
    try:
      r = requests.put(endpoint, data=str(_payload))
      results.append(r.content)
    except requests.exceptions.RequestException as e:
      print e
  return results