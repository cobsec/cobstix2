from cobstix2 import *
from cobbox import *

def main():
  
  aso = ASObject(number=123)
  aso1 = ASObject(number=456)
  ip4 = IPv4Address(value='1.2.3.4', description='something')
  ip41 = IPv4Address(value='2.3.4.5', description='something else')

  con = Container()
  ip4_ref = con.add_object(ip4)
  ip41_ref = con.add_object(ip41)
  net = NetworkTraffic(protocols=['tcp', 'ipv4', 'http'], start='2017-02-15T15:18:23.146000Z')
  net.src_ref = ip4_ref
  net.dst_ref = ip41_ref
  count = con.add_object(net)
  print con
  



if __name__ == '__main__':
  main()