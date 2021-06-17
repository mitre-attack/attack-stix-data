# Utilities

This folder contains utilities for the maintenance of the data in this repository. They are provided for maintainers within the ATT&CK team and to enable the ATT&CK community to release their own extensions of this dataset on similarly formatted repositories. 

The intention and use of the scripts is described below.

## [generate-collection-index.py](generate-collection-index.py)

This script is intended to regenerate the collection index which references the collections in this repository. 

### Usage:
```
python3 util/generate-collection-index.py \
    "MITRE ATT&CK" \
    "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community. \n\nhttps://attack.mitre.org" \
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/" \
    -collections enterprise-attack mobile-attack ics-attack
```

## [index-to-md.py](index-to-md.py)

This script is intended to transform a machine readable collection index JSON file into a human readable Markdown file. 

### Usage: 
```
python3 util/index-to-md.py
```

## [bundle-to-filesystem.py](bundle-to-filesystem.py)

This script generates a [FileSystemSource](https://stix2.readthedocs.io/en/latest/guide/filesystem.html) from the input STIX bundles or collection folders.

### Usage:
```
python3 util/bundle-to-filesystem.py -folders enterprise-attack mobile-attack ics-attack
```

