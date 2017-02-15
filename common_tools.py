import sys
import json
from uuid import uuid4, uuid3, NAMESPACE_URL
import gc
import inspect
import re
import traceback
import ast

from vocab import *

def ns_uuid(_type, _string):
  return str(_type) + '--' + str(uuid3(NAMESPACE_URL, _string))

def uuid(_type):
  return str(_type) + '--' + str(uuid4())

def is_id(id_ref):
  try:
    if re.match('.{1,64}--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', id_ref):
      #print 'id PASSED: ' + id_ref
      return True
    else:
      raise ValueError('[cobstix2] {id_ref} is not a valid identity reference format'.format(id_ref=repr(id_ref)))
  except (ValueError), e:
    traceback.print_exc()
    sys.exit(0)

def is_timestamp(timestamp):
  try:
    if re.match('\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z', timestamp):
      #print 'timestamp PASSED: ' + timestamp
      return True
    else:
      raise ValueError('[cobstix2] {timestamp} is not a valid timestamp format'.format(timestamp=repr(timestamp)))
  except (ValueError), e:
    traceback.print_exc()
    sys.exit(0)

def is_datamarking(object, granular_markings):
  try:
    for marking in granular_markings:
      if type(marking) is not dict:
        raise TypeError('[cobstix2] {marking} is not a valid input type; Expected dict.'.format(marking=repr(marking)))
      else:
        if is_id(marking['marking_ref']):
          for selector in marking['selectors']:
            datamarking_attribute = getattr(object, selector)
    return True
  except (TypeError, KeyError, AttributeError), e:
    traceback.print_exc()
    sys.exit(0)

def is_killchain(killchains):
  try:
    for killchain in killchains:
      if type(killchain) is not dict:
        raise TypeError('[cobstix2] {killchain} is not a valid input type; Expected dict.'.format(killchain=repr(killchain)))
      elif killchain['phase_name'] not in VOCABS['kill_chain'][killchain['kill_chain_name']]:
          raise ValueError('[cobstix2] {killchain} contains non-vocab kill-chain data.'.format(killchain=repr(killchain)))
    return True
  except (TypeError, KeyError, AttributeError), e:
    traceback.print_exc()
    sys.exit(0)

def is_relationship(relationship):
  relationship_type = relationship[0]
  source_ref = relationship[1]
  target_ref = relationship[2]
  source_type = source_ref.split('--')[0]
  target_type = target_ref.split('--')[0]
  try:
    if is_id(source_ref) and is_id(target_ref) and target_type in VOCABS['relationship'][source_type][relationship_type]:
      return True
    else:
      raise ValueError('[cobstix2] {relationship} is not a valid relationship construct'.format(relationship=repr(relationship)))
  except (KeyError, ValueError), e:
    traceback.print_exc()
    sys.exit(0)

def is_cybox_object(object):
  return True

def is_cybox_object_ref(object, reference):
  return True

def is_timestamp(timestamp):
  try:
    if re.match('\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z', timestamp):
      #print 'timestamp PASSED: ' + timestamp
      return True
    else:
      raise ValueError('[cobstix2] {timestamp} is not a valid timestamp format'.format(timestamp=repr(timestamp)))
  except (ValueError), e:
    traceback.print_exc()
    sys.exit(0)

def is_valid(input, _type, vocab_ref):
  try:
    if type(input) is not _type:
      raise TypeError('[cobstix2] {input} is not a valid input type {type}; Expected {_type}'.format(input=repr(input), type=repr(type(input)), _type=repr(_type)))

    if vocab_ref is not None:
      if vocab_ref == 'timestamp':
        return is_timestamp(input)

      if vocab_ref == 'id':
        return is_id(input)

      if vocab_ref == 'killchain':
        return is_killchain(input)

      if vocab_ref == 'relationship':
        return is_relationship(input)

      if vocab_ref == 'cybox-object':
        return is_cybox_object(input)
    
      if type(input) is str:
        input = [input]

      voc_lst = vocab_ref.rsplit('-', 2)
      if voc_lst[-2] == 'label':
        test_list = VOCABS[voc_lst[-1]][voc_lst[-2]][voc_lst[-3]]
        test_input = input
      else:
        voc_lst = vocab_ref.rsplit('-', 1)
        test_list = VOCABS[voc_lst[-1]][voc_lst[-2]]
        test_input = input
      if not set(input).issubset(test_list):
        raise ValueError('[cobstix2] {test_input} is not a valid {vocab_ref} vocab (required)'.format(test_input=repr(test_input), vocab_ref=repr(vocab_ref)))
    return True
  except (ValueError, TypeError), e:
    traceback.print_exc()
    sys.exit(0)

def err_required(obj_type, attribute):
  try:
    raise ValueError('[cobstix2] {attribute} attribute required for {type} object initialisation'.format(attribute=repr(attribute), type=repr(obj_type)))
  except (ValueError), e:
    traceback.print_exc()
    sys.exit(0)