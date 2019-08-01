from cobstix2 import *
from cobbox import *

def main():
  
  net_traff_container = create_network_traffic_object(['tcp','ipv4','http'], '1.2.3.4', '2.3.4.5')
  #print net_traff_container
  net_traff_dict = net_traff_container.__dict__

  net_traff_ref = max(net_traff_dict, key=int)
  print net_traff_dict[str(net_traff_ref)]

  domain = DomainName(value='badguy.com')
  print domain

  win_key = WindowsRegistryKey(key='some_key')
  print win_key
  win_key.add_registry_value('value_name', '42', 'REG_QWORD')
  print win_key
 


if __name__ == '__main__':
  main()