# Changes to ATT&CK in STIX 2.1

## 28 October 2025 - ATT&CK Spec v3.3.0

Changes to ATT&CK in STIX for the October 2025 ATT&CK Content Release (ATT&CK v18.0)

* Added Analytic objects. For detailed information about the representation of Analytics in ATT&CK/STIX, please see the [ATT&CK Data Model schema documentation](https://mitre-attack.github.io/attack-data-model/docs/reference/schemas/sdo/analytic.schema).
* Added Detection Strategy objects. For detailed information about the representation of Detection Strategies in ATT&CK/STIX, please see the [ATT&CK Data Model schema documentation](https://mitre-attack.github.io/attack-data-model/docs/reference/schemas/sdo/detection-strategy.schema).
* Deprecated Data Source objects. These objects will be removed in ATT&CK Spec v4.
* Modified Data Component objects:
  * Assigned an ATT&CK ID to each Data Component object.
  * Added the `x_mitre_log_sources` property. See the [ATT&CK Data Model schema documentation](https://mitre-attack.github.io/attack-data-model/docs/reference/schemas/sdo/data-component.schema#xmitrelogsources) for a description of this new property.
  * Deprecated the `x_mitre_data_source_ref` property. This property will be removed from the spec entirely in ATT&CK Spec v4.
* Modified Technique objects:
  * Deprecated the following properties, which will be removed from the spec entirely in ATT&CK Spec v4.
    * `x_mitre_detection`
    * `x_mitre_system_requirements`
    * `x_mitre_permissions_required`
    * `x_mitre_effective_permissions`
    * `x_mitre_data_sources`
    * `x_mitre_defense_bypassed`
    * `x_mitre_remote_support`
* Deprecated the `x_mitre_data_component` `--detects-->` `attack-pattern` relationship object. These will be removed in ATT&CK Spec v4. This has been replaced by the `x_mitre_detection_strategy` `--detects-->` `attack-pattern` relationship object.

## 22 April 2025

There are no changes to the data model in the April 2025 ATT&CK Content Release (ATT&CK v17.0)

## 31 October 2024

There are no changes to the data model in the October 2024 ATT&CK Content Release (ATT&CK v16.0)

## 23 April 2024

There are no changes to the data model in the April 2024 ATT&CK Content Release (ATT&CK v15.0)

## 31 October 2023 - ATT&CK Spec v3.2.0

Changes to ATT&CK in STIX for October 2023 ATT&CK Content Release (ATT&CK v14.0)

* Added Asset objects. For detailed information about the representation of Assets in ATT&CK/STIX, please see the assets section of the [USAGE document](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#assets).

## 25 April 2023 - ATT&CK Spec v3.1.0

Changes to ATT&CK in STIX for April 2023 ATT&CK Content Release (ATT&CK v13.0)

* Restored the `labels` property for ICS mitigation objects. This property documents security controls for ICS mitigations.

## 25 October 2022 - ATT&CK Spec v3.0.0

Changes to ATT&CK in STIX for October 2022 ATT&CK Content Release (ATT&CK v12.0)

* Added Campaign objects. For detailed information about the representation of Campaigns in ATT&CK/STIX, please see the campaign section of the [USAGE document](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#campaigns).

## 21 October 2021 - ATT&CK Spec v2.1.0
Changes to ATT&CK in STIX for October 2021 ATT&CK Content Release (ATT&CK v10)

| Feature | [Available in STIX 2.0](https://github.com/mitre/cti) | [Available in STIX 2.1](https://github.com/mitre-attack/attack-stix-data) |
|:--------|:-----------------------------------------------------:|:-------------------------------------------------------------------------:|
| Added full objects for data sources and data components. See [the data sources section of the USAGE document](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#data-sources-and-data-components) for more information about data sources, data components, and their relationships with techniques. | :white_check_mark: | :white_check_mark: |
| Added `x_mitre_attack_spec_version` field to all object types. This field tracks the version of the ATT&CK Spec used by the object. Consuming software can use this field to determine if the data format is supported; if the field is absent the object will be assumed to use ATT&CK Spec version `2.0.0`. | :x: | :white_check_mark: |

## 21 June 2021 - ATT&CK Spec v2.0.0
Initial release of ATT&CK in STIX 2.1.

ATT&CK in STIX 2.0 (ATT&CK Spec < 2.0.0) can be found on our [MITRE/CTI](https://github.com/mitre/cti) GitHub repository which contains the same dataset but in STIX 2.0 and without many of the quality-of-life features available in ATT&CK Spec v2.0.0+.

| Feature | [Available in STIX 2.0](https://github.com/mitre/cti) | [Available in STIX 2.1](https://github.com/mitre-attack/attack-stix-data) |
|:--------|:-----------------------------------------------------:|:-------------------------------------------------------------------------:|
| Added `x_mitre_modified_by_ref` field to all object types. This field tracks the identity of the individual or organization which created the current _version_ of the object. | :x: | :white_check_mark: | 
| Added `x_mitre_domains` field to all non-relationship objects. This field tracks the domains the object is found in. | :x: | :white_check_mark: |
| Added [collection](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md) objects to track information about specific releases of the dataset and to allow the dataset to be imported into [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/). | :x: | :white_check_mark: |
| Added a [collection index](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md) to list the contents of this repository and to allow the data to be imported into [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/). | :x: | :white_check_mark: |