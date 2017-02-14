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
  
  ind = Indicator(name='[EXAMPLE] Malicious infrastructure IP address', description='[EXAMPLE] Fake indicator generated to demonstrate stix2 object composition for CTI Adapter sharing.', labels=['malicious-activity'], pattern="ipv4-addr:value = '1.2.3.4'", kill_chain_phases=[{'kill_chain_name':'pre-post', 'phase_name':'pre-attack'}])
  coa = CourseOfAction(name='[EXAMPLE] REPORT Sightings to NCSC', description='[EXAMPLE] Should this Indicator be observed in connection to your network, please report the activity to NCSC using a STIX Sighting Object.')
  atp = AttackPattern(name='[EXAMPLE] Pre-positioning of malicious infrastructure', kill_chain_phases=[{'kill_chain_name':'pre-post', 'phase_name':'pre-attack'}])
  rel_ind_atp = Relationship('indicates', ind.id, atp.id)
  rel_coa_atp = Relationship('mitigates', coa.id, atp.id)
  
  all_sdo = get_all_SDO()
  #report_list = []
  for sdo in all_sdo:
    if sdo.type != 'marking-definition' and sdo.type != 'identity' and sdo.type != 'malware':
      sdo.object_marking_refs([tlpamber.id])
      #report_list.append(sdo.id)

  #rep = Report(name='[FoW] Basic FoW Example', object_refs=report_list)
  #all_sdo.append(rep)
  bun = Bundle(objects=[ind, coa, atp, rel_coa_atp, rel_ind_atp])

  #with open('out.json', 'wb') as f:
    #f.write(str(bun))

  print bun


if __name__ == '__main__':
  main()