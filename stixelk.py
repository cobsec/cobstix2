from cobstix2 import *
import requests
import json
from config import settings

def query(value):
  try:
    query_type = USER
  except KeyError:
    print "[cobstix2] Could not read kb_type from kb settings in config.ini"
    sys.exit(0)

  if query_type == 'elk':
    _index = settings('stix')['created_by_ref']
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