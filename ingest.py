from cobstix2 import *
from common_tools import *
import ast

def main():

  obj = file_to_obj('out.json')
  print obj
  if obj.type == 'bundle':
    output = {'pattern': [], 'coa': [], 'context': []}
    for _dict in obj.objects:
      object = dict_to_obj(_dict)
      if object.type == 'indicator':
        output['pattern'].append(object.pattern)
      if object.type == 'course-of-action':
        output['coa'].append(object.name)
      if object.type == 'attack-pattern':
        output['context'].append(object.name)

  print output

if __name__ == '__main__':
  main()