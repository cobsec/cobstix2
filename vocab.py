VOCABS = {
  'ov' : {
    'label' : {
      'indicator' : [
        'anomalous-activity',
        'anonymization',
        'benign',
        'compromised',
        'malicious-activity',
        'attribution'
      ],
      'malware' : [
        'adware',
        'backdoor',
        'bot',
        'ddos',
        'dropper',
        'exploit-kit',
        'keylogger',
        'ransomware',
        'remote-access-trojan',
        'resource-exploitation',
        'rogue-security-software',
        'rootkit',
        'screen-capture',
        'spyware',
        'trojan',
        'virus',
        'worm'
      ],
      'report' : [
        'threat-report',
        'attack-pattern',
        'campaign',
        'identity',
        'indicator',
        'malware',
        'observed-data',
        'threat-actor',
        'tool',
        'vulnerability'
      ],
      'threat-actor' : [
        'activist',
        'competitor',
        'crime-syndicate',
        'criminal',
        'hacker',
        'insider-accidental',
        'insider-disgruntled',
        'nation-state',
        'sensationalist',
        'spy',
        'terrorist'
      ],
      'tool' : [
        'denial-of-service',
        'exploitation',
        'information-gathering',
        'network-capture',
        'credential-exploitation',
        'remote-access',
        'vulnerability-scanning'
      ],
    },
    'industry-sector' : [
      'agriculture',
      'aerospace',
      'automotive',
      'communications',
      'construction',
      'defense',
      'education',
      'energy',
      'entertainment',
      'financial-services',
      'government-national',
      'government-regional',
      'government-local',
      'government-public-services',
      'healthcare',
      'hospitality-leisure',
      'infrastructure',
      'insurance',
      'manufacturing',
      'mining',
      'non-profit',
      'pharmaceuticals',
      'retail',
      'technology',
      'telecommunications',
      'transportation',
      'utilities'
    ],
    'identity-class' : [
      'individual',
      'group',
      'organization',
      'class',
      'unknown'
    ],
    'attack-resource-level' : [
      'individual',
      'club',
      'contest',
      'team',
      'organization',
      'government',
    ],
    'attack-motivation' : [
      'accidental',
      'coercion',
      'dominance',
      'ideology',
      'notoriety',
      'organizational-gain',
      'personal-gain',
      'personal-satisfaction',
      'revenge',
      'unpredictable',
    ],
    'threat-actor-sophistication' : [
      'none',
      'minimal',
      'intermediate',
      'advanced',
      'expert',
      'innovator',
      'strategic',
    ],
    'threat-actor-role' : [
      'agent',
      'director',
      'independent',
      'infrastructure-architect',
      'infrastructure-operator',
      'malware-author',
      'sponsor',
    ],
  },
  'kill_chain' : {
    'pre-post' : [
      'pre-attack',
      'post-attack',
    ],
  },
  'relationship' : {
    'common' : [
        'duplicate-of',
        'derived-from',
        'related-to',
    ],
    'attack-pattern' : {
      'targets' : [
        'vulnerability',
        'identity',
      ],
      'uses' : [
        'malware',
        'tool',
      ],
    },
    'campaign' : {
      'attributed-to' : [
        'intrusion-set',
        'threat-actor',
      ],
      'targets' : [
        'identity',
        'vulnerability',
      ],
      'uses' : [
        'attack-pattern',
        'malware',
        'tool',
      ],
    },
    'course-of-action' : {
      'mitigates' : [
        'attack-pattern',
        'malware',
        'tool',
        'vulnerability',
      ],
    },
    'indicator' : {
      'indicates' : [
        'attack-pattern',
        'campaign',
        'intrusion-set',
        'malware',
        'threat-actor',
        'tool',
      ],
    },
    'intrusion-set' : {
      'attributed-to' : [
        'threat-actor',
      ],
      'targets' : [
        'identity',
        'vulnerability',
      ],
      'uses' : [
        'attack-pattern',
        'malware',
        'tool',
      ],
    },
    'malware' : {
      'targets' : [
        'identity',
        'vulnerability',
      ],
      'uses' : [
        'tool',
      ],
      'variant-of' : [
        'malware',
      ],
    },
    'threat-actor' : {
      'attributed-to' : [
        'identity',
      ],
      'impersonates' : [
        'identity',
      ],
      'targets' : [
        'identity',
        'vulnerability',
      ],
      'uses' : [
        'attack-pattern',
        'malware',
        'tool',
      ],
    },
    'tool' : {
      'targets' : [
        'identity',
        'vulnerability',
      ],
    },
  }
}