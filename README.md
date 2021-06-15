# ATT&CK® STIX Data

This repository contains the [MITRE ATT&CK](https://attack.mitre.org) dataset represented in STIX 2.1 JSON. If you are looking for STIX 2.0 JSON representing ATT&CK, please see our [MITRE/CTI](https://github.com/mitre/cti) GitHub repository which contains the same dataset but in STIX 2.0 and without the [collections](#collections) features provided on this repository.

See the [USAGE](/USAGE.md) document for information on using this content with [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2).

The full contents of this repository is listed in [index.md](/index.md).

## MITRE ATT&CK

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

https://attack.mitre.org

## STIX

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

https://oasis-open.github.io/cti-documentation/


## Collections

The data in this repository includes Collections and a Collection Index for use with the [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) project. These data formats also enable record keeping of ATT&CK versions and extensions. 

- [Collections](/docs/collections.md#collections)

  Collections are sets of related ATT&CK objects, and may be used to represent specific releases of a dataset such as “Enterprise ATT&CK v9.0” or any other set of objects one may want to share with someone else. 

  Each ATT&CK release on this repository is itself a collection. A full list of collections on this repository can be found in [index.md](index.md).

- [Collection Indexes](/docs/collections.md#collection-indexes)

  Collection indexes are organized lists of collections intended to ease their distribution to data consumers. Collection indexes track individual releases of given collections (e.g Enterprise v7, Enterprise v8, Enterprise v9) and allow applications such as the Workbench to check if new releases have been published. Collection Indexes are represented as JSON objects.
  
  The ATT&CK collection index for the contents of this repository is [index.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json), with a human-readable representation available in [index.md](index.md).

More information about collections and collection indexes can be found in the ATT&CK Workbench's [collections document](docs/collections.md).

## Repository Structure

```
.
├─ enterprise-attack ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ [1] Collection folder 
│   ├─ enterprise-attack.json ∙∙∙∙∙∙∙∙∙∙∙ [2] Most recent version of the collection
│   ├─ enterprise-attack-9.0 ∙∙∙∙∙∙∙∙∙∙∙∙ [3] Collection version folder
│   │   ├─ enterprise-attack-9.0.json ∙∙∙ [4] Collection version bundle
│   │   ├─ attack-pattern ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ [5] attack-patterns in that version
│   │   ├─ course-of-action ∙∙∙∙∙∙∙∙∙∙∙∙∙     course-of-actions in that version
│   │   └─ [other object types]
│   └─ [other releases of Enterprise ATT&CK]
└─ [other collections]
```
1. Each Collection folder represents a domain of ATT&CK
2. The STIX bundle in the root of the collection folder will always be the most recent version of the collection. Use this if you want to reference the domain _in-general_ and not a specific release of the dataset.
3. The collection version folder contains a specific release of ATT&CK.
4. The collection version bundle represents the data of that specific version. It also contains a [collection object](#collections) to allow it to be imported into the [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend).
5. Each collection version folder is a [FileSystemSource](https://stix2.readthedocs.io/en/latest/guide/filesystem.html), with sub-folders of each object type. The FileSystemSource has the same content as the collection version bundle, but unlike the collection version bundle it cannot be imported into the ATT&CK Workbench.

The full list of collections and versions stored within this repository can be found in [index.md](/index.md).

