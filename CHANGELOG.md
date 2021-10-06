# Changes to ATT&CK in STIX 2.1

## 30 October 2021 - ATT&CK Spec v2.1.0
Changes to ATT&CK in STIX for October 2021 ATT&CK Content Release (ATT&CK v10)

- Added full objects for data sources and data components. See [the data sources section of the USAGE document](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#data-sources-and-data-components) for more information about data sources, data components, and their relationships with techniques.
- Added `x_mitre_attack_spec_version` to `x-mitre-collection` objects. This field tracks the version of the ATT&CK Spec used by the collection. Consuming software can use this field to determine if the version of a given collection's version of the ATT&CK data model is supported.

## 21 June 2021 - ATT&CK Spec v2.0.0
Initial release of ATT&CK in STIX 2.1.

ATT&CK in STIX 2.0 (ATT&CK Spec < 2.0.0) can be found on our [MITRE/CTI](https://github.com/mitre/cti) GitHub repository which contains the same dataset but in STIX 2.0 and without many of the quality-of-life features available in ATT&CK Spec v2.0.0+.