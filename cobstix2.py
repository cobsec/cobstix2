import sys
import json
from uuid import uuid4, uuid3, NAMESPACE_URL
from hashlib import sha1
import datetime
from pprint import pprint
import gc
import requests
import inspect
import re

from vocab import *
from config import settings

USER = settings('stix')['created_by_string']
ELK = settings('kb_elk')['kb_ip']

def ns_uuid(_type, _string):
  return str(_type) + '--' + str(uuid3(NAMESPACE_URL, _string))

def uuid(_type):
  return str(_type) + '--' + str(uuid4())

def is_timestamp(timestamp):
  return re.match('\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z', timestamp)

def is_valid(input, vocab_ref):
  if type(input) is str:
    input = [input]

  if type(input) is list:
    voc_lst = vocab_ref.rsplit('-', 2)
    if voc_lst[-2] == 'label':
      test_list = VOCABS[voc_lst[-1]][voc_lst[-2]][voc_lst[-3]]
      test_input = input
    else:
      voc_lst = vocab_ref.rsplit('-', 1)
      test_list = VOCABS[voc_lst[-1]][voc_lst[-2]]
      test_input = input
    if set(input).issubset(test_list):
      return True
    else:
      raise ValueError('[cobstix2] {test_input} is not a valid {vocab_ref} vocab (required)'.format(test_input=repr(test_input), vocab_ref=repr(vocab_ref)))
  else:
    raise TypeError('[cobstix2] {test_input} is not a valid input type {type}'.format(test_input=repr(test_input), type=repr(type(input))))

def err_required(obj_type, attribute):
  raise ValueError('[cobstix2] {attribute} attribute required for {type} object initialisation'.format(attribute=repr(attribute), type=repr(obj_type)))



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

  def set_timestamp(object, attribute, timestamp):
    if is_timestamp(timestamp):
      setattr(object, attribute, timestamp)
    else:
      raise ValueError('[cobstix2] {timestamp} is not a valid timestamp format'.format(timestamp=repr(timestamp)))

  def set_attribute(object, attribute, input, vocab_ref=None):
    #Will set an attribute of type list or string with optional vocab check
    # Consider putting an input type checker here for str/list/id/boolean, etc. Would need the spec types captured in a vocab dict, perhaps?
      if vocab_ref is not None:
        if is_valid(input, vocab_ref):
          setattr(object, attribute, input)
      else:
        setattr(object, attribute, input)

  def set_labels(self, labels):
    if labels is None:
      if self.type in VOCABS:
        raise ValueError('[cobstix2] {labels} is not a valid {object} label (required)'.format(labels=repr(labels), object=repr(self.type)))
    else:
      vocab_ref = self.type + '-label-ov'
      self.set_attribute('labels', labels, vocab_ref)

    """
    # Commenting this out for now as it includes an 'add' functionality which implies version control
    # Making it just a 'setter' would be preferable, but setting on initialisation for MULTIPLE DICTIONARY ENTRIES IN A LIST is difficult to figure out at the moment
    # May need to create a custom 'kill_chain_setter' like the tlp/datamarking - perhaps consider enumerating all kill_chain dictionary entries in vocab for easy import
    def add_kill_chain_phase(self, kill_chain_name, phase_name):
    #Manually add a kill chain phase to an Indicator object
      try:
        if phase_name in VOCAB['kill_chain'][kill_chain_name][kill_chain_name]:
          if not hasattr(self, 'kill_chain_phases'):
            self.kill_chain_phases = []
          self.kill_chain_phases.append({'kill_chain_name' : kill_chain_name, 'phase_name' : phase_name})
      except KeyError:
        raise ValueError('[cobstix2] {kill_chain_name} is not a recognised Kill Chain'.format(kill_chain_name=repr(kill_chain_name)))
    """

    def import_kill_chain_phases(self, kill_chain_phases):
      #Import Kill Chain Phases from a fully formed dictionary - doesn't check vocabs as some may use different kill chain definitions
      if type(kill_chain_phases) is list:
        self.kill_chain_phases = kill_chain_phases
      else:
        raise ValueError('[cobstix2] Failed to import Kill Chain list')

  def set_created_by_ref(self, name, identity_class):
    id_ref = ns_uuid('identity', name)
    _identity = query(id_ref)
    if _identity is False:
      _identity = Identity(name=name, identity_class=identity_class, id=id_ref)
    else:
      self.created_by_ref = _identity[0].id
    return _identity

  def set_tlp(self, definition, selectors=None):
    tlp_id = ns_uuid('marking-definition', definition)
    try:
      del self.object_marking_refs
    except AttributeError:
      pass
    try:
      del self.granular_markings
    except AttributeError:
      pass
    _tlp = False
    if _tlp is False:
      _tlp = TLPMarking(definition=definition, id=tlp_id)
    if selectors is None:
      self.object_marking_refs = [tlp_id]
    else:
      self.granular_markings = [{'marking_ref': tlp_id, 'selectors': selectors}]
    return _tlp

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

class Campaign(SDO):
  type = 'campaign'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = Campaign.type
    super(Campaign, self).__init__(*args, **kwargs)
    if 'aliases' in kwargs:
      self.set_attribute('aliases', kwargs.get('aliases'))
    if 'first_seen' in kwargs:
      self.set_timestamp('first_seen', kwargs.get('first_seen'))
    if 'last_seen' in kwargs:
      self.set_timestamp('last_seen', kwargs.get('last_seen'))
    if 'objective' in kwargs:
      self.set_objective(kwargs.get('objective'))

  def set_objective(self, objective):
    self.objective = objective

class CourseOfAction(SDO):
  type = 'course-of-action'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = CourseOfAction.type
    super(CourseOfAction, self).__init__(*args, **kwargs)

class Identity(SDO):
  type = 'identity'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    if not 'identity_class' in kwargs:
      err_required(self.type, 'identity_class')
    self.type = Identity.type
    super(Identity, self).__init__(*args, **kwargs)
    self.set_attribute('identity_class', kwargs.get('identity_class'), 'identity-class-ov')
    if 'sectors' in kwargs:
      self.set_attribute('sectors', kwargs.get('sectors'), 'industry-sector-ov')
    if 'contact_information' in kwargs:
      self.set_contacts(kwargs.get('contact_information'))

  def set_contacts(contact_information):
    self.contact_information = contact_information

class Indicator(SDO):
  type = 'indicator'
  def __init__(self, *args, **kwargs):
    if not 'pattern' in kwargs:
      err_required(self.type, 'pattern')
    self.type = Indicator.type
    super(Indicator, self).__init__(*args, **kwargs)
    self.pattern = kwargs.get('pattern')
    if 'valid_from' in kwargs:
      self.set_timestamp('valid_from', kwargs.get('valid_from'))
    else:
      self.valid_from = self.created

    if 'valid_until' in kwargs:
      self.set_timestamp('valid_until', kwargs.get('valid_until'))
    if 'kill_chain_phases' in kwargs:
      self.import_kill_chain_phases(kwargs.get('kill_chain_phases'))

class IntrusionSet(SDO):
  type = 'intrusion-set'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = IntrusionSet.type
    super(IntrusionSet, self).__init__(*args, **kwargs)
    if 'aliases' in kwargs:
      self.set_attribute('aliases', kwargs.get('aliases'))
    if 'first_seen' in kwargs:
      self.set_timestamp('first_seen', kwargs.get('first_seen'))
    if 'last_seen' in kwargs:
      self.set_timestamp('last_seen', kwargs.get('last_seen'))
    if 'goals' in kwargs:
      self.set_attribute('goals',kwargs.get('goals'))
    if 'resource_level' in kwargs:
      self.set_attribute('resource_level', kwargs.get('resource_level'), 'attack-resource-level-ov')
    if 'primary_motivation' in kwargs:
      self.set_attribute('primary_motivation', kwargs.get('primary_motivation'), 'attack-motivation-ov')
    if 'secondary_motivations' in kwargs:
      self.set_attribute('secondary_motivations', kwargs.get('secondary_motivations'), 'attack-motivation-ov')

class Malware(SDO):
  type = 'malware'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = Malware.type
    super(Malware, self).__init__(*args, **kwargs)
    if 'kill_chain_phases' in kwargs:
      self.import_kill_chain_phases(kwargs.get('kill_chain_phases'))

class Report(SDO):
  type = 'report'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = Report.type
    super(Report, self).__init__(*args, **kwargs)
    self.set_timestamp('published', kwargs.get('published', datetime.datetime.utcnow().isoformat('T') + 'Z'))
    
  def set_object_refs(self, object_refs):
    self.object_refs = []
    if type(object_refs) is list:
      self.object_refs = object_refs
    else:
      self.object_refs.append(object_refs)

class ThreatActor(SDO):
  type = 'threat-actor'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = ThreatActor.type
    super(ThreatActor, self).__init__(*args, **kwargs)
    if 'aliases' in kwargs:
      self.set_attribute('aliases', kwargs.get('aliases'))
    if 'roles' in kwargs:
      self.set_attribute('roles', kwargs.get('roles'), 'threat-actor-role-ov')
    if 'goals' in kwargs:
      self.set_attribute('goals',kwargs.get('goals'))
    if 'sophistication' in kwargs:
      self.set_attribute('sophistication', kwargs.get('sophistication'), 'threat-actor-sophistication-ov')
    if 'resource_level' in kwargs:
      self.set_attribute('resource_level', kwargs.get('resource_level'), 'attack-resource-level-ov')
    if 'primary_motivation' in kwargs:
      self.set_attribute('primary_motivation', kwargs.get('primary_motivation'), 'attack-motivation-ov')
    if 'secondary_motivations' in kwargs:
      self.set_attribute('secondary_motivations', kwargs.get('secondary_motivations'), 'attack-motivation-ov')
    if 'personal_motivations' in kwargs:
      self.set_attribute('personal_motivations', kwargs.get('personal_motivations'), 'attack-motivation-ov')

class Tool(SDO):
  type = 'tool'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = Tool.type
    super(Tool, self).__init__(*args, **kwargs)
    if 'kill_chain_phases' in kwargs:
      self.import_kill_chain_phases(kwargs.get('kill_chain_phases'))
    if 'tool_version' in kwargs:
      self.set_tool_version(kwargs.get('tool_version'))

  def set_tool_version(self, tool_version):
    self.set_attribute('tool_version', tool_version)

class Vulnerability(SDO):
  type = 'vulnerability'
  def __init__(self, *args, **kwargs):
    if not 'name' in kwargs:
      err_required(self.type, 'name')
    self.type = Vulnerability.type
    return super(Vulnerability, self).__init__(*args, **kwargs)

class Relationship(SDO):
  type = 'relationship'
  def __init__(self, *args, **kwargs):
    self.type = Relationship.type
    super(Relationship, self).__init__(*args, **kwargs)
    try:
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
    except IndexError:
      raise IndexError('[cobstix2] Relationship object requires Relationship(<relationship_type>, <source_ref>, <target_ref>) for initialisation.')

class Sighting(SDO):
  type = 'sighting'
  def __init__(self, *args, **kwargs):
    if not 'sighting_of_ref' in kwargs:
      err_required(self.type, 'sighting_of_ref')
    self.type = Sighting.type
    super(Sighting, self).__init__(*args, **kwargs)
    if 'sighting_of_ref' in kwargs:
      self.set_attribute('sighting_of_ref', kwargs.get('sighting_of_ref'))
    if 'first_seen' in kwargs:
      self.set_timestamp('first_seen', kwargs.get('first_seen'))
    if 'last_seen' in kwargs:
      self.set_timestamp('last_seen', kwargs.get('last_seen'))
    if 'count' in kwargs:
      self.set_attribute('count', kwargs.get('count'))
    if 'observed_data_refs' in kwargs:
      self.set_attribute('observed_data_refs', kwargs.get('observed_data_refs'))
    if 'where_sighted_refs' in kwargs:
      self.set_attribute('where_sighted_refs', kwargs.get('where_sighted_refs'))
    if 'summary' in kwargs:
      self.set_attribute('summary', kwargs.get('summary'))

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