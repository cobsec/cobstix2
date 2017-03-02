cobstix2
===========

An experimental python library implementing the STIX 2.0 spec as python objects (NOT an official library, just having a go!) Not complete by a long stretch, just getting something together so I can easily create sample objects for experimentation.

:Spec: http://stixproject.github.io/stix2.0/

File list:
 - cobstix2: Core stix2 implementation (very work in progress!)
 - cobbox: Core cybox2 implementation (even more work in progress while I figure out how the referenced containers can be built)
 - common_tools: Shared functions for manipulating stix objects
 - vocab: Set vocabs for use in stix object construction (mostly open-vocab)
 - stixelk: Some functions to interact with an elk stack to push stix2 objects to a knowledge base
 - config.py/.ini: Basic config management
Sample scripts:
 - grizzlysteppe: [BROKEN] Implementation of GS report (US-CERT) in stix2. Need supdating for new API bindings
 - test: Generic testing ground for trying out the libraries
 - ingest: Using the cobstix2 library to ingest stix2 objects
 - sample: CTI Adapter object production example
 - watchlist: Generating 'watchlist' report objects using the stix2 libraries
 - stix221: VERY SPECIFIC implementation for downgrading a specific instance of stix2 objects to stix1 (not a generic translator, just for a specific use case)


Major Update with commit: 7639f77151a13a26cfb151c54adcaede544f18d9
 - Starting to update towards RC4 spec, primarily SDO parent and Indicator objects (main targets of below updates too...other objects tfo)
 - Validation checking on initialisation for spec requirements (eg: labels mandatory on certain objects, patterns on Indicators, etc)
 - So now you shouldn't be able to initialise an Indicator variable without specifying the required fields. Interesting user-experience debate to be had around that, but I think it's valid for the implementation
 - Bundles fixed to RC4 spec ('objects' attribute rather than specific object type arrays...THANK YOU OASIS CTI TC!!!)
 - Added a config.ini as I was getting too many global vars. Obviously I'm referencing a local ELK VM for testing purposes - feel free to add your knowledge base (kb) of choice!
 - enrich.py is a local enrichment function which I haven't included here...sorry, that might break things! Delete lines 89-99 (of grizzlysteppe.py) to avoid issues
 - test.py is just a muck about with some simple examples of object creation
 - grizzlysteppe.py uses JAR-16-20296A.csv (from US-CERT publication) to re-interpret in a stix2 format using the library. It's pretty basic, but shows how to improve on linearly structured cyber threat intelligence using stix2

Lots more updates to follow! Will be working through RC4 and updating other classes to improve compliance and validation on initialisation.

Follow-up commit: c057c9ad2b0d7345daf4dcae01f78e8459984971
 - New objects added such as Vulnerability and STUB'd ones should be complete now
 - Abstracted attribute setting to a generic 'set_attribute' handler which allows for centralised validation. This does mean that optional attributes are a bit trickier for the user to set now (ie: can't really do object.attribute = 'value'). I'm not sure how I feel about this...it definitely makes the library easier to build/change, but the focus of the user experience becomes making sure that everything is set on initialisation. Those that are optional can then be set with specific set_specific_attribute functions for each object type (that will reference the generic setter). I think that's fine, but will need to go through and write the optional setters

TODO:
 - Write a full test harness to test valid object creation (pass), missing required fields (fail) and incorrect vocab usage where required (fail)
 - Re-write data marking (set_tlp) to handle any types of data marking
 - Start to investigate 'add' functionality and other functions which might cause object version changes...not sure how best to do that at the moment
