# ATT&CK® STIX Data

### This is a Persian-translated derivative of MITRE ATT&CK® data. Original data © MITRE Corporation. Not officially endorsed by MITRE.


[MITRE ATT&CK](https://attack.mitre.org) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community. 

This repository contains the MITRE ATT&CK dataset represented in STIX 2.1 JSON collections. If you are looking for STIX 2.0 JSON representing ATT&CK, please see our [MITRE/CTI](https://github.com/mitre/cti) GitHub repository which contains the same dataset but in STIX 2.0 and without the collections features provided on this repository.

## Repository Structure

```
.
├─ enterprise-attack ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ [1] Collection folder for Enterprise
│   ├─ enterprise-attack.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙ [2] Most recent Enterprise release
│   ├─ enterprise-attack-9.0.json ∙∙∙∙∙∙∙∙∙∙ [3] Enterprise ATT&CK v9.0 collection
│   └─ [other releases of Enterprise ATT&CK]
├─ mobile-attack
│   └─ [Mobile ATT&CK releases]
├─ ics-attack
│   └─ [ATT&CK for ICS releases]
├─ index.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ [4] Collection index JSON
└─ index.md ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ [5] Collection index markdown
```

**[1]** Each domain of ATT&CK (Enterprise, Mobile and ICS) is represented as a series of  STIX 2.1 [collection](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections) bundles representing the individual releases of the dataset, organized within the collection folders.

**[2]** Each domain includes a STIX 2.1 collection bundle without version markings which will always match the most recent release of the dataset.

**[3]** Each STIX bundle in the collection folders represents a specific release of the collection. Learn more in our [collections](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections) document.

**[4]** The [collection index JSON](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json) lists the contents of this repository in a machine-readable format. Learn more in our [collections](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes) document.

**[5]** The [collection index markdown](/index.md) lists the contents of this repository in a human-readable format.

## Supporting Documentation

### [STIX](https://oasis-open.github.io/cti-documentation/)

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

### [Collections](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collections)

Collections are sets of related ATT&CK objects, and may be used to represent specific releases of a dataset such as “Enterprise ATT&CK v9.0” or any other set of objects one may want to share with someone else. 

Each ATT&CK release on this repository is itself a collection. A full list of collections on this repository can be found in [index.md](index.md).

### [Collection Indexes](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#collection-indexes)

Collection indexes are organized lists of collections intended to ease their distribution to data consumers. Collection indexes track individual releases of given collections (e.g Enterprise v7, Enterprise v8, Enterprise v9) and allow applications such as the [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) to check if new releases have been published. Collection indexes are represented as JSON objects.
  
The ATT&CK collection index for the contents of this repository is [index.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json), with a human-readable representation available in [index.md](index.md).

### [Usage](/USAGE.md)

The Usage document includes documentation of the ATT&CK data model as well as code examples for accessing and querying this content with [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2). Additional information and tooling for maintaining the data in this repository is available in the [util](/util) folder.

## Notice 

Copyright 2020-2025 The MITRE Corporation. Approved for public release. Case number 19-3504.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)