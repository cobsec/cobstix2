import sys
import json
import datetime
from pprint import pprint
import traceback

from vocab import *
from config import settings
from common_tools import *

USER = settings('stix')['created_by_string']
ELK = settings('kb_elk')['kb_ip']

def get_all_SDO():
  SDO_list = []
  for obj in gc.get_objects():
    if isinstance(obj, SDO):
      SDO_list.append(obj)
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

def file_to_obj(_filename):
  # Imports stix objects from local fiule (eg: something.json)
  with open(_filename, 'rb') as f:
    raw = f.read()
  obj_dict = ast.literal_eval(raw)
  obj = dict_to_obj(obj_dict)
  return obj

class SDO(object):
  def __init__(self, *args, **kwargs):
    self.created(kwargs.get('created', datetime.datetime.utcnow().isoformat('T') + 'Z'))
    self.modified(kwargs.get('modified', self.created))
    self.id(kwargs.get('id', uuid(self.type)))
    self.created_by_ref(kwargs.get('created_by_ref', ns_uuid('identity', USER)))
    self.labels(kwargs.get('labels', None))
    self.name(kwargs.get('name', None))
    self.description(kwargs.get('description', None))
    self.revoked(kwargs.get('revoked', None))
    self.external_references(kwargs.get('external_references', None))
    self.object_marking_refs(kwargs.get('object_marking_refs', None))
    self.granular_markings(kwargs.get('granular_markings', None))

  def set_attribute(object, attribute, input, _type, vocab_ref=None, required=False):
    if input is not None:
      if vocab_ref == 'datamarking':
        if is_datamarking(object, input):
          setattr(object, attribute, input)
      elif is_valid(input, _type, vocab_ref):
        setattr(object, attribute, input)
    else:
      if required:
        err_required(object.type, attribute)

  def labels(self, _labels):
    vocab_ref = self.type + '-label-ov'
    self.set_attribute('labels', _labels, list, vocab_ref, False)

  def created(self, _created):
    self.set_attribute('created', _created, str, 'timestamp', True)

  def modified(self, _modified):
    if self.type != 'marking-definition':
      self.set_attribute('modified', _modified, str, None, True)

  def id(self, _id):
    self.set_attribute('id', _id, str, 'id', True)

  def created_by_ref(self, _created_by_ref):
    self.set_attribute('created_by_ref', _created_by_ref, str, 'id', True)

  def name(self, _name):
    required = True
    if self.type == 'relationship' or self.type == 'marking-definition':
      required = False
    self.set_attribute('name', _name, str, None, required)

  def description(self, _description):
    self.set_attribute('description', _description, str)

  def revoked(self, _revoked):
    self.set_attribute('revoked', _revoked, bool)

  def external_references(self, _external_references):
    self.set_attribute('external_references', _external_references, list)

  def object_marking_refs(self, _object_marking_refs):
    self.set_attribute('object_marking_refs', _object_marking_refs, list)

  def granular_markings(self, _granular_markings):
    self.set_attribute('granular_markings', _granular_markings, list, 'datamarking')

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))

class AttackPattern(SDO):
  type = 'attack-pattern'
  def __init__(self, *args, **kwargs):
    self.type = AttackPattern.type
    super(AttackPattern, self).__init__(*args, **kwargs)
    self.kill_chain_phases(kwargs.get('kill_chain_phases', None))

  def kill_chain_phases(self, _kill_chain_phases):
    self.set_attribute('kill_chain_phases', _kill_chain_phases, list, 'killchain')

class Campaign(SDO):
  type = 'campaign'
  def __init__(self, *args, **kwargs):
    self.type = Campaign.type
    super(Campaign, self).__init__(*args, **kwargs)
    self.aliases(kwargs.get('aliases', None))
    self.first_seen(kwargs.get('first_seen', None))
    self.last_seen(kwargs.get('last_seen', None))
    self.objective(kwargs.get('objective', None))

  def aliases(self, _aliases):
    self.set_attribute('aliases', _aliases, list)

  def first_seen(self, _first_seen):
    self.set_attribute('first_seen', _first_seen, str, 'timestamp')

  def last_seen(self, _last_seen):
    self.set_attribute('last_seen', _last_seen, str, 'timestamp')

  def objective(self, _objective):
    self.set_attribute('objective', _objective, str)

class CourseOfAction(SDO):
  type = 'course-of-action'
  def __init__(self, *args, **kwargs):
    self.type = CourseOfAction.type
    super(CourseOfAction, self).__init__(*args, **kwargs)

class Identity(SDO):
  type = 'identity'
  def __init__(self, *args, **kwargs):
    self.type = Identity.type
    if 'id_seed' in kwargs:
      kwargs['id'] = ns_uuid(self.type, kwargs.get('id_seed'))
      del kwargs['id_seed']
    super(Identity, self).__init__(*args, **kwargs)
    self.identity_class(kwargs.get('identity_class', None))
    self.sectors(kwargs.get('sectors', None))
    self.contact_information(kwargs.get('contact_information', None))

  def identity_class(self, _identity_class):
    self.set_attribute('identity_class', _identity_class, str, 'identity-class-ov', True)

  def sectors(self, _sectors):
    self.set_attribute('sectors', _sectors, str, 'industry-sector-ov', False)

  def contact_information(self, _contact_information):
    self.set_attribute('contact_information', _contact_information, str)

class Indicator(SDO):
  type = 'indicator'
  def __init__(self, *args, **kwargs):
    self.type = Indicator.type
    super(Indicator, self).__init__(*args, **kwargs)
    self.pattern(kwargs.get('pattern', None))
    self.valid_from(kwargs.get('valid_from', self.created))
    self.valid_until(kwargs.get('valid_until', None))
    self.kill_chain_phases(kwargs.get('kill_chain_phases', None))

  def pattern(self, _pattern):
    self.set_attribute('pattern', _pattern, str, None, True)

  def valid_from(self, _valid_from):
    self.set_attribute('valid_from', _valid_from, str, 'timestamp')

  def valid_until(self, _valid_until):
    self.set_attribute('valid_until', _valid_until, str, 'timestamp')

  def kill_chain_phases(self, _kill_chain_phases):
    self.set_attribute('kill_chain_phases', _kill_chain_phases, list, 'killchain')

class IntrusionSet(SDO):
  type = 'intrusion-set'
  def __init__(self, *args, **kwargs):
    self.type = IntrusionSet.type
    super(IntrusionSet, self).__init__(*args, **kwargs)
    self.aliases(kwargs.get('aliases', None))
    self.first_seen(kwargs.get('first_seen', None))
    self.last_seen(kwargs.get('last_seen', None))
    self.goals(kwargs.get('goals', None))
    self.resource_level(kwargs.get('resource_level', None))
    self.primary_motivation(kwargs.get('primary_motivation', None))
    self.secondary_motivations(kwargs.get('secondary_motivations', None))

  def aliases(self, _aliases):
    self.set_attribute('aliases', _aliases, list)

  def first_seen(self, _first_seen):
    self.set_attribute('first_seen', _first_seen, str, 'timestamp')

  def last_seen(self, _last_seen):
    self.set_attribute('last_seen', _last_seen, str, 'timestamp')

  def goals(self, _goals):
    self.set_attribute('goals', _goals, str)

  def resource_level(self, _resource_level):
    self.set_attribute('resource_level', _resource_level, str, 'attack-resource-level-ov')

  def primary_motivation(self, _primary_motivation):
    self.set_attribute('primary_motivation', _primary_motivation, str, 'attack-motivation-ov')

  def secondary_motivations(self, _secondary_motivations):
    self.set_attribute('secondary_motivations', _secondary_motivations, str, 'attack-motivation-ov')

class Malware(SDO):
  type = 'malware'
  def __init__(self, *args, **kwargs):
    self.type = Malware.type
    super(Malware, self).__init__(*args, **kwargs)
    self.is_family(kwargs.get('is_family', None))
    self.kill_chain_phases(kwargs.get('kill_chain_phases', None))
    self.first_seen(kwargs.get('first_seen', None))
    self.last_seen(kwargs.get('last_seen', None))
    self.certificates(kwargs.get('certificates', None))
    self.strings(kwargs.get('strings', None))
    self.code_snippets(kwargs.get('code_snippets', None))
    self.network_traffic(kwargs.get('network_traffic', None))
    self.actions(kwargs.get('actions', None))
    self.sample_metadata(kwargs.get('sample_metadata', None))
    self.sample(kwargs.get('sample', None))
    self.extra_analysis_data(kwargs.get('extra_analysis_data', None))
    self.classifications(kwargs.get('classifications', None))

  def is_family(self, _is_family):
    self.set_attribute('is_family', _is_family, bool)

  def kill_chain_phases(self, _kill_chain_phases):
    self.set_attribute('kill_chain_phases', _kill_chain_phases, list, 'killchain')

  def first_seen(self, _first_seen):
    self.set_attribute('first_seen', _first_seen, str, 'timestamp')

  def last_seen(self, _last_seen):
    self.set_attribute('last_seen', _last_seen, str, 'timestamp')

  def certificates(self, _certificates):
    self.set_attribute('certificates', _certificates, dict, None)

  def strings(self, _strings):
    self.set_attribute('strings', _strings, list, None)

  def code_snippets(self, _code_snippets):
    self.set_attribute('code_snippets', _code_snippets, dict, None)

  def network_traffic(self, _network_traffic):
    self.set_attribute('network_traffic', _network_traffic, dict, None)

  def actions(self, _actions):
    self.set_attribute('actions', _actions, list, None)

  def sample_metadata(self, _sample_metadata):
    self.set_attribute('sample_metadata', _sample_metadata, dict, None)

  def sample(self, _sample):
    self.set_attribute('sample', _sample, dict, None)

  def extra_analysis_data(self, _extra_analysis_data):
    self.set_attribute('extra_analysis_data', _extra_analysis_data, dict, None)

  def classifications(self, _classifications):
    self.set_attribute('classifications', _classifications, list, None)

class ObservedData(SDO):
  type = 'observed-data'
  def __init__(self, *args, **kwargs):
    self.type = ObservedData.type
    super(ObservedData, self).__init__(*args, **kwargs)
    self.first_observed(kwargs.get('first_observed', None))
    self.last_obseved(kwargs.get('last_obseved', self.first_observed))
    self.number_observed(kwargs.get('number_observed', None))
    self.objects(kwargs.get('objects', None))

  def first_observed(self, _first_observed):
    self.set_attribute('first_observed', _first_observed, str, 'timestamp', True)

  def last_obseved(self, _last_obseved):
    self.set_attribute('last_obseved', _last_obseved, str, 'timestamp', True)

  def number_observed(self, _number_observed):
    self.set_attribute('number_observed', _number_observed, int, None, True)

  def objects(self, _objects):
    self.set_attribute('objects', _objects, dict, None, True)

class Report(SDO):
  type = 'report'
  def __init__(self, *args, **kwargs):
    self.type = Report.type
    super(Report, self).__init__(*args, **kwargs)
    self.published(kwargs.get('published', datetime.datetime.utcnow().isoformat('T') + 'Z'))
    self.object_refs(kwargs.get('object_refs', None))

  def published(self, _published):
    self.set_attribute('published', _published, str, 'timestamp', True)

  def object_refs(self, _object_refs):
    self.set_attribute('object_refs', _object_refs, list, None, True)

class ThreatActor(SDO):
  type = 'threat-actor'
  def __init__(self, *args, **kwargs):
    self.type = ThreatActor.type
    super(ThreatActor, self).__init__(*args, **kwargs)
    self.aliases(kwargs.get('aliases', None))
    self.roles(kwargs.get('roles', None))
    self.goals(kwargs.get('goals', None))
    self.sophistication(kwargs.get('sophistication', None))
    self.resource_level(kwargs.get('resource_level', None))
    self.primary_motivation(kwargs.get('primary_motivation', None))
    self.secondary_motivations(kwargs.get('secondary_motivations', None))

  def aliases(self, _aliases):
    self.set_attribute('aliases', _aliases, str)

  def roles(self, _roles):
    self.set_attribute('roles', _roles, str, 'threat-actor-role-ov')

  def goals(self, _goals):
    self.set_attribute('goals', _goals, str)

  def sophistication(self, _sophistication):
    self.set_attribute('sophistication', _sophistication, str, 'threat-actor-sophistication-ov')

  def resource_level(self, _resource_level):
    self.set_attribute('resource_level', _resource_level, str, 'attack-resource-level-ov')

  def primary_motivation(self, _primary_motivation):
    self.set_attribute('primary_motivation', _primary_motivation, str, 'attack-motivation-ov')

  def secondary_motivations(self, _secondary_motivations):
    self.set_attribute('secondary_motivations', _secondary_motivations, str, 'attack-motivation-ov')

  def personal_motivation(self, _personal_motivation):
    self.set_attribute('personal_motivation', _personal_motivation, str, 'attack-motivation-ov')

class Tool(SDO):
  type = 'tool'
  def __init__(self, *args, **kwargs):
    self.type = Tool.type
    super(Tool, self).__init__(*args, **kwargs)
    self.tool_version(kwargs.get('tool_version', None))
    self.kill_chain_phases(kwargs.get('kill_chain_phases', None))

  def tool_version(self, _tool_version):
    self.set_attribute('tool_version', _tool_version, str)

  def kill_chain_phases(self, _kill_chain_phases):
    self.set_attribute('kill_chain_phases', _kill_chain_phases, list, 'killchain')

class Vulnerability(SDO):
  type = 'vulnerability'
  def __init__(self, *args, **kwargs):
    self.type = Vulnerability.type
    return super(Vulnerability, self).__init__(*args, **kwargs)

class Relationship(SDO):
  type = 'relationship'
  def __init__(self, *args, **kwargs):
    self.type = Relationship.type
    super(Relationship, self).__init__(*args, **kwargs)
    try:
      if 'relationship_type' in kwargs and 'source_ref' in kwargs and 'target_ref' in kwargs:
        self.set_relationship(kwargs.get('relationship_type', None), kwargs.get('source_ref', None), kwargs.get('target_ref', None))
      elif len(args) > 2:
        self.set_relationship(args[0], args[1], args[2])
      else:
        raise ValueError('[cobstix2] Relationship object requires Relationship(<relationship_type>, <source_ref>, <target_ref>) for initialisation.')
    except ValueError:
      traceback.print_exc()
      sys.exit(0)

  def set_relationship(self, _type, _source, _target):
    if _type is not None and _source is not None and _target is not None:
      if is_valid([_type, _source, _target], list, 'relationship'):
        setattr(self, 'relationship_type', _type)
        setattr(self, 'source_ref', _source)
        setattr(self, 'target_ref', _target)
    else:
      err_required(self.type, 'relationship')

class Sighting(SDO):
  type = 'sighting'
  def __init__(self, *args, **kwargs):
    self.type = Sighting.type
    super(Sighting, self).__init__(*args, **kwargs)
    self.sighting_of_ref(kwargs.get('sighting_of_ref', None))
    self.first_seen(kwargs.get('first_seen', None))
    self.last_seen(kwargs.get('last_seen', None))
    self.count(kwargs.get('count', None))
    self.observed_data_refs(kwargs.get('observed_data_refs', None))
    self.where_sighted_refs(kwargs.get('where_sighted_refs', None))
    self.summary(kwargs.get('summary', None))

  def sighting_of_ref(self, _sighting_of_ref):
    self.set_attribute('sighting_of_ref', _sighting_of_ref, str, 'id', True)

  def first_seen(self, _first_seen):
    self.set_attribute('first_seen', _first_seen, str, 'timestamp')

  def last_seen(self, _last_seen):
    self.set_attribute('last_seen', _last_seen, str, 'timestamp')

  def count(self, _count):
    self.set_attribute('count', _count, int)

  def observed_data_refs(self, _observed_data_refs):
    self.set_attribute('count', _observed_data_refs, list)

  def where_sighted_refs(self, _where_sighted_refs):
    self.set_attribute('count', _where_sighted_refs, list)

  def summary(self, _summary):
    self.set_attribute('count', _summary, bool)

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
    self.definition(kwargs.get('definition', None))

  def definition(self, _definition):
    self.set_attribute('definition', _definition, dict, None, True)

class Bundle():
  type = 'bundle'
  def __init__(self, *args, **kwargs):
    self.type = Bundle.type
    self.id = uuid(self.type)
    self.spec_version = '2.0'
    self.objects(kwargs.get('objects', None))

  def objects(self, _objects):
    try:
      self.objects = []
      if type(_objects) is list:
        for _object in _objects:
          if type(_object) is dict:
            self.objects.append(_object)
          else:
            self.objects.append(_object.__dict__)
      else:
        raise TypeError('[cobstix2] {_objects} is not a valid object list to be Bundled (required)'.format(_objects=repr(_objects)))
    except (TypeError), e:
      traceback.print_exc()
      sys.exit(0)

  def __repr__(self):
    return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))