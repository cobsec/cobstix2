import sys
import json
from uuid import uuid4, uuid3, NAMESPACE_URL
from hashlib import sha1
import datetime
from pprint import pprint
import gc
import requests
import inspect

#Default values
USER = 'default'
ELK = 'http://192.168.137.141:9200/'

def ns_uuid(_type, _string):
  return str(_type) + '--' + str(uuid3(NAMESPACE_URL, _string))

def uuid(_type):
  return str(_type) + '--' + str(uuid4())

BUNDLE_PROPERTIES = {
  'attack-pattern' : 'attack_patterns',
  'campaign' : 'campaigns',
  'course-of-action' : 'courses_of_action',
  'identity' : 'identities',
  'indicator' : 'indicators',
  'intrusion-set' : 'intrusion_sets',
  'malware' : 'malware',
  'marking-definition' : 'marking_definitions',
  'observed-data' : 'observed_data',
  'relationship' : 'relationships',
  'report' : 'reports',
  'sighting' : 'sightings',
  'threat-actor' : 'threat_actors',
  'tool' : 'tools',
  'vulnerability' : 'vulnerabilities',
  'custom-object' : 'custom_objects',
}

class SDO(object):
  def __init__(self, *args, **kwargs):
    self.created_by_ref = kwargs.get('created_by_ref', ns_uuid('identity', USER))
    self.created = kwargs.get('created', datetime.datetime.utcnow().isoformat('T') + 'Z')
    self.modified = kwargs.get('modified', self.created)
    self.version = kwargs.get('version', '1')
    self.id = kwargs.get('id', uuid(self.type))
    if 'labels' in kwargs:
      self.labels = kwargs.get('labels')

  def set_text(self, name, description=None):
    self.name = name
    if description is not None:
      self.description = description

  def set_labels(self, labels=None):
    if labels is None:
      self.labels = []
    else:
      self.labels = labels

  def set_tlp(self, definition, selectors=None):
    tlp_id = ns_uuid('marking-definition', definition)
    _tlp = query_by_ref('elk', tlp_id)
    if _tlp is False:
      _tlp = TLPMarking(definition=definition)
    if not selectors:
      self.object_marking_refs = [tlp_id]
    else:
      try:
        self.granular_markings.append({'marking_ref': tlp_id, 'selectors': selectors})
      except AttributeError:
        self.granular_markings = [{'marking_ref': tlp_id, 'selectors': selectors}]
    return _tlp  

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

  def set_first_seen(self, first_seen=None):
    if first_seen is None:
      self.first_seen = self.created
    else:
      self.first_seen = first_seen

  def set_objective(self, objective=None):
    self.objective = objective

class CourseOfAction(SDO):
  type = 'course-of-action'
  def __init__(self, *args, **kwargs):
    self.type = CourseOfAction.type
    super(CourseOfAction, self).__init__(*args, **kwargs)

class Indicator(SDO):
  type = 'indicator'
  def __init__(self, *args, **kwargs):
    self.type = Indicator.type
    super(Indicator, self).__init__(*args, **kwargs)
    self.valid_from = kwargs.get('valid_from', self.created)
    
  def set_pattern(self, pattern, pattern_lang=None, pattern_lang_version=None):
    self.pattern = pattern
    if pattern_lang:
      self.pattern_lang = pattern_lang
    if pattern_lang_version:
      self.pattern_lang_version = pattern_lang_version

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
  def __init__(self, objects=None):
    self.type = Bundle.type
    self.id = uuid(self.type)
    self.spec_version = '2.0'

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

def bundle(*objects):
  bundle = Bundle()
  for obj in objects:
    _property = str(BUNDLE_PROPERTIES[obj.type])
    try:
      getattr(bundle, _property).append(obj.__dict__)      
    except AttributeError:
      setattr(bundle, _property, [obj.__dict__])
  return bundle

def get_all_SDO():
  SDO_list = []
  for obj in gc.get_objects():
    if isinstance(obj, SDO):
      SDO_list.append(obj)
  return SDO_list

def dict_to_obj(_dict):

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

def query_by_ref(query_type, _id):
  if query_type == 'local':
    for obj in gc.get_objects():
      if isinstance(obj, SDO):
        if obj.id == _id:
          return obj
    return False
  elif query_type == 'elk':
    _index = 'cobsec'
    _type = _id.split('--')[0]
    _id = _id.split('--')[1]
    endpoint = ELK + '%s/%s/%s' % (_index, _type, _id)
    r = requests.get(endpoint)
    json_content = r.json()
    try:
      new_obj = dict_to_obj(json_content["_source"])
      return new_obj
    except AttributeError:
      return False
  else:
    return False

def put_elk(*_payloads):
  results = []
  print _payloads
  for _payload in _payloads:
    print _payload
    if isinstance(_payload, SDO) or isinstance(_payload, Bundle):
      _index = USER
      _type = _payload.type
      _id = _payload.id.split('--')[1]
    else:
      return None
    endpoint = ELK + '%s/%s/%s' % (_index, _type, _id)
    r = requests.put(endpoint, data=str(_payload))
    results.append(r.content)
  return results