from cobstix2 import *

def main():

  # Admin:
  tlpamber = TLPMarking(name='TLP Amber', definition={'tlp':'amber'})
  creator = Identity(name='Creator ID: cobsec', identity_class='individual', id_seed='cobsec')
  
  #Better FoW:
  # IN REPORT:
  #  Indicator object with pattern for some IP addresses
  #  2 x Course of Action asking for checking and reporting respectively
  #  The malware from which the indicator was extracted
  #  Relationships for coas to malware (mitigates)
  #  Relationships from indicator to malware (indicates)
  # IN BUNDLE:
  #  All of above
  #  Report object referencing the above
  #  TLP Marking
  #  Identity of creator
  
  ind = Indicator(name='[EXAMPLE] PIVY Pre-exploitation Delivery Infrastructure targeting friendly victim', description='[EXAMPLE] Fake indicator generated to demonstrate stix2 object composition. In this example, PIVY infrastructure (1.2.3.4) has been observed attempting to make incoming connections to friendly IP address (2.3.4.5)', labels=['malicious-activity'], pattern="[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '2.3.4.5' AND network-traffic:src_ref.value = '1.2.3.4']", kill_chain_phases=[{'kill_chain_name':'pre-post', 'phase_name':'pre-attack'}])
  coa1 = CourseOfAction(name='[EXAMPLE] BLOCK Inbound Connections', description='[EXAMPLE] Where possible, deploy this indicator to network sensors, Intrusion Detection Systems and/or other protective monitoring devices to BLOCK outbound connections to infrastructure using this indicator pattern.')
  coa2 = CourseOfAction(name='[EXAMPLE] REPORT Sightings to NCSC', description='[EXAMPLE] Should this Indicator be observed in connection to your network, please report the activity to NCSC using a STIX Sighting Object.')
  mal = Malware(name='[EXAMPLE] Poison Ivy', kill_chain_phases=[{'kill_chain_name':'pre-post', 'phase_name':'pre-attack'}])
  rel_ind_mal = Relationship('indicates', ind.id, mal.id)
  rel_coa1_mal = Relationship('mitigates', coa1.id, mal.id)
  rel_coa2_mal = Relationship('mitigates', coa2.id, mal.id)
  
  all_sdo = get_all_SDO()
  report_list = []
  for sdo in all_sdo:
    if sdo.type != 'marking-definition' and sdo.type != 'identity' and sdo.type != 'malware':
      sdo.object_marking_refs = tlpamber.id
      report_list.append(sdo.id)

  rep = Report(name='[FoW] Basic FoW Example', object_refs=report_list)
  all_sdo.append(rep)
  bun = Bundle(objects=all_sdo)

  print bun


if __name__ == '__main__':
  main()