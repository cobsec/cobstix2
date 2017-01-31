cobstix2
===========

An experimental python library implementing the STIX 2.0 spec as python objects (NOT an official library, just having a go!) Not complete by a long stretch, just getting something together so I can easily create sample objects for experimentation.

:Spec: http://stixproject.github.io/stix2.0/

Major Update with commit: 7639f77151a13a26cfb151c54adcaede544f18d9
 - Starting to update towards RC4 spec, primarily SDO parent and Indicator objects (main targets of below updates too...other objects tfo)
 - Validation checking on initialisation for spec requirements (eg: labels mandatory on certain objects, patterns on Indicators, etc)
 - So now you shouldn't be able to initialise an Indicator variable without specifying the required fields. Interesting user-experience debate to be had around that, but I think it's valid for the implementation
 - Bundles fixed to RC4 spec ('objects' attribute rather than specific object type arrays...THANK YOU OASIS CTI TC!!!)
 - Added a config.ini as I was getting too many global vars. Obviously I'm referencing a local ELK VM for testing purposes - feel free to add your knowledge base (kb) of choice!
 - enrich.py is a local enrichment function which I haven't included here...sorry, that might break things! Delete lines 89-99 to avoid issues
 - test.py is just a muck about with some simple examples of object creation
 - grizzlysteppe.py uses JAR-16-20296A.csv (from US-CERT publication) to re-interpret in a stix2 format using the library. It's pretty basic, but shows how to improve on linearly structured cyber threat intelligence using stix2

Lots more updates to follow! Will be working through RC4 and updating other classes to improve compliance and validation on initialisation.
