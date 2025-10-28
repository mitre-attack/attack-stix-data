# Introduction

This document describes how to query and manipulate the ATT&CK data in this repository. It is divided into two sections:

-   [Accessing ATT&CK data in python](#accessing-attck-data-in-python), which describes different methodologies that can be used to load the ATT&CK data into a script.
-   [Python recipes](#Python-Recipes), which provides python3 examples of common ways to query the ATT&CK data once loaded.

Both sections heavily utilize the [stix2 python library](https://github.com/oasis-open/cti-python-stix2). Please refer to the [STIX2 Python API Documentation](https://stix2.readthedocs.io/en/latest/) for more information on how to work with STIX programmatically.

For information about the ATT&CK data model, object types, and specification details, please refer to the [ATT&CK Specification](https://github.com/mitre-attack/attack-data-model/blob/main/docs/SPEC.md).

We also recommend reading the [ATT&CK Design and Philosophy Paper](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf), which describes high-level overall approach, intention, and usage of ATT&CK.

## Table of Contents

<!-- generated with https://ecotrust-canada.github.io/markdown-toc/ -->
<!-- note: generator turns ATT&CK into att-ck, but GitHub section links for that substring are attck (no hyphen). -->

- [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
- [Accessing ATT\&CK data in python](#accessing-attck-data-in-python)
  - [Requirements and imports](#requirements-and-imports)
    - [stix2](#stix2)
    - [taxii2client](#taxii2client)
  - [Access local content](#access-local-content)
    - [Access the most recent version via MemoryStore](#access-the-most-recent-version-via-memorystore)
    - [Access a specific version via MemoryStore](#access-a-specific-version-via-memorystore)
  - [Access live content](#access-live-content)
    - [Access from the ATT\&CK TAXII server](#access-from-the-attck-taxii-server)
    - [Access the most recent version from GitHub via requests](#access-the-most-recent-version-from-github-via-requests)
    - [Access a specific version from GitHub via requests](#access-a-specific-version-from-github-via-requests)
  - [Getting a list of versions](#getting-a-list-of-versions)
  - [Access multiple domains simultaneously](#access-multiple-domains-simultaneously)
- [Python recipes](#python-recipes)
  - [Getting an object](#getting-an-object)
    - [By STIX ID](#by-stix-id)
    - [By ATT\&CK ID](#by-attck-id)
    - [By name](#by-name)
    - [By alias](#by-alias)
  - [Getting multiple objects](#getting-multiple-objects)
    - [Objects by type](#objects-by-type)
      - [Getting techniques or sub-techniques](#getting-techniques-or-sub-techniques)
      - [Getting software](#getting-software)
    - [Objects by content](#objects-by-content)
    - [Techniques by platform](#techniques-by-platform)
    - [Techniques by tactic](#techniques-by-tactic)
    - [Tactics by matrix](#tactics-by-matrix)
    - [Objects created or modified since a given date](#objects-created-or-modified-since-a-given-date)
  - [Getting related objects](#getting-related-objects)
    - [Relationships microlibrary](#relationships-microlibrary)
    - [Getting techniques used by a group's software](#getting-techniques-used-by-a-groups-software)
  - [Working with deprecated and revoked objects](#working-with-deprecated-and-revoked-objects)
    - [Removing revoked and deprecated objects](#removing-revoked-and-deprecated-objects)
    - [Getting a revoking object](#getting-a-revoking-object)

# Accessing ATT&CK data in python

There are several ways to acquire the ATT&CK data in Python. All of them will provide an object
implementing the DataStore API and can be used interchangeably with the recipes provided in the [Python recipes](#Python-Recipes) section.

This section utilizes the [stix2 python library](https://github.com/oasis-open/cti-python-stix2). Please refer to the [STIX2 Python API Documentation](https://stix2.readthedocs.io/en/latest/) for more information on how to work with STIX programmatically.

## Requirements and imports

Before installing requirements, we recommend setting up a virtual environment:

1. Create virtual environment:
    - macOS and Linux: `python3 -m venv env`
    - Windows: `py -m venv env`
2. Activate the virtual environment:
    - macOS and Linux: `source env/bin/activate`
    - Windows: `env/Scripts/activate.bat`

### stix2

[stix2 can be installed by following the instructions on their repository](https://github.com/oasis-open/cti-python-stix2#installation). Imports for the recipes in this repository can be done from the base package, for example:

```python
from stix2 import Filter
```

However, if you are aiming to extend the ATT&CK dataset with new objects or implement complex workflows, you may need to use the `v21` specifier for some imports. This ensures that the objects use the STIX 2.1 API instead of the STIX 2.0 API. For example:

```python
from stix2.v21 import AttackPattern
```

You can see a full list of the classes which have versioned imports [here](https://stix2.readthedocs.io/en/latest/api/stix2.v21.html).

### taxii2client

Information on the TAXII 2.1/STIX2.1 server can be found in [the TAXII server repository](https://github.com/mitre-attack/attack-workbench-taxii-server).

## Access local content

Many users may opt to access the ATT&CK content via a local copy of the STIX data on this repo. This can be advantageous for several reasons:

-   Doesn't require internet access after the initial download
-   User can modify the ATT&CK content if desired
-   Downloaded copy is static, so updates to the ATT&CK catalog won't cause bugs in automated workflows. User can still manually update by cloning a fresh version of the data

### Access the most recent version via MemoryStore

The collection bundle without a version marking will always match the most recent release of the dataset. To access the content of the release you can simply load it into a MemoryStore:

```python
from stix2 import MemoryStore

src = MemoryStore()
src.load_from_file("enterprise-attack/enterprise-attack.json")
```

### Access a specific version via MemoryStore

To access a specific version of the dataset, you can simply load the file with the desired version number:

```python
import os
from stix2 import MemoryStore

def get_attack_version(domain, version):
    """get ATT&CK STIX data for a given domain and version. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    ms = MemoryStore()
    ms.load_from_file(os.path.join(domain, f"{domain}-{version}.json"))
    return ms

src = get_attack_version("enterprise-attack", "18.0")
```

## Access live content

Some users may instead prefer to access "live" ATT&CK content over the internet. This is advantageous for several reasons:

-   Always stays up to date with the evolving ATT&CK catalog
-   Doesn't require an initial download of the ATT&CK content, generally requires less setup

### Access from the ATT&CK TAXII server

Information on the TAXII 2.1/STIX2.1 server can be found in [the TAXII server repository](https://github.com/mitre-attack/attack-workbench-taxii-server).

### Access the most recent version from GitHub via requests

Users can alternatively access the data from MITRE/CTI using HTTP requests, and load the resulting content into a MemoryStore.
While typically the TAXII method is more desirable for "live" access, this method can be useful if you want to
access data on a branch of the MITRE/CTI repo (the TAXII server only holds the master branch) or in the case of a TAXII server outage.

```python
import requests
from stix2 import MemoryStore

def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_data_from_branch("enterprise-attack")
```

### Access a specific version from GitHub via requests

```python
import requests
from stix2 import MemoryStore

def get_data_from_version(domain, version):
    """get the ATT&CK STIX data for the given version from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}-{version}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_data_from_version("enterprise-attack", "18.0")
```

## Getting a list of versions

The [collection index](/index.json) on this repository contains a full list of versions for each domain of ATT&CK. See our [collections document](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/main/docs/collections.md#collection-indexes) for more information about the format of collection indexes. You can also find a human-readable version of that file in [index.md](/index.md).

The collection index was added in the upgrade to STIX 2.1 and is not available for [the STIX 2.0 dataset](https://github.com/mitre/cti).

## Access multiple domains simultaneously

Because ATT&CK is stored in multiple domains (as of this writing, enterprise-attack, mobile-attack and ics-attack), the above methodologies will only allow you to work
with a single domain at a time. While oftentimes the hard separation of domains is advantageous, occasionally it is useful to combine
domains into a single DataStore. Use any of the methods above to acquire the individual datastores, and then use the following approach to combine them into
a single CompositeDataSource:

```python
from stix2 import CompositeDataSource

src = CompositeDataSource()
src.add_data_sources([enterprise_attack_src, mobile_attack_src, ics_attack_src])
```

You can then use this CompositeDataSource just as you would the DataSource for an individual domain.

# Python recipes

Below are example python recipes which can be used to work with ATT&CK data. They assume the existence of an object implementing the DataStore API. Any of the methods outlined in the [Accessing ATT&CK data in python](#accessing-ATTCK-Data-in-Python) section should provide an object implementing this API.

This section utilizes the [stix2 python library](https://github.com/oasis-open/cti-python-stix2). Please refer to the [STIX2 Python API Documentation](https://stix2.readthedocs.io/en/latest/) for more information on how to work with STIX programmatically. See also the section on [Requirements and imports](#requirements-and-imports).

## Getting an object

The recipes in this section address how to query the dataset for a single object.

### By STIX ID

The following recipe can be used to retrieve an object according to its STIX ID. This is typically the preferred way to retrieve objects when working with ATT&CK data because STIX IDs are guaranteed to be unique.

```python
g0075 = src.get("intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142")
```

### By ATT&CK ID

The following recipe can be used to retrieve an object according to its ATT&CK ID:

```python
from stix2 import Filter

g0075 = src.query([ Filter("external_references.external_id", "=", "G0075") ])[0]
```

Note: in prior versions of ATT&CK, mitigations had 1:1 relationships with techniques and shared their technique's ID. Therefore the above method does not work properly for techniques because technique ATTT&CK IDs are not truly unique. By specifying the STIX type you're looking for as `attack-pattern` you can avoid this issue.

```python
from stix2 import Filter

t1134 = src.query([
    Filter("external_references.external_id", "=", "T1134"),
    Filter("type", "=", "attack-pattern")
])[0]
```

The old 1:1 mitigations causing this issue are deprecated, so you can also filter them out that way — see [Removing revoked and deprecated objects](#Removing-revoked-and-deprecated-objects).

### By name

The following recipe retrieves an object according to its name:

```python
from stix2 import Filter

def get_technique_by_name(thesrc, name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    return thesrc.query(filt)
# get the technique titled "System Information Discovery"
get_technique_by_name(src, 'System Information Discovery')
```

### By alias

The following methodology can be used to find the group corresponding to a given alias:

```python
from stix2 import Filter

def get_group_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])[0]

get_group_by_alias(src, 'Cozy Bear')
```

## Getting multiple objects

The recipes in this section address how to query the dataset for multiple objects.

&#9888; When working with queries to return objects based on a set of characteristics, it is likely that you'll end up with a few objects which are no longer maintained by ATT&CK. These are objects marked as deprecated or revoked. We keep these outdated objects around so that workflows depending on them don't break, but we recommend you avoid using them when possible. Please see the section [Working with deprecated and revoked objects](#Working-with-deprecated-and-revoked-objects) for more information.

### Objects by type

See [The ATT&CK data model](#The-ATTCK-Data-Model) for mappings of ATT&CK type to STIX type.

```python
from stix2 import Filter

# use the appropriate STIX type in the query according to the desired ATT&CK type
groups = src.query([ Filter("type", "=", "intrusion-set") ])
```

#### Getting techniques or sub-techniques

ATT&CK Techniques and sub-techniques are both represented as `attack-pattern` objects. Therefore further parsing is necessary to get specifically techniques or sub-techniques.

```python
from stix2 import Filter

def get_techniques_or_subtechniques(thesrc, include="both"):
    """Filter Techniques or Sub-Techniques from ATT&CK Enterprise Domain.
    include argument has three options: "techniques", "subtechniques", or "both"
    depending on the intended behavior."""
    if include == "techniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
    elif include == "subtechniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern')
        ])
    else:
        raise RuntimeError("Unknown option %s!" % include)

    return query_results


subtechniques = get_techniques_or_subtechniques(src, "subtechniques")
subtechniques = remove_revoked_deprecated(subtechniques) # see https://github.com/mitre/cti/blob/master/USAGE.md#removing-revoked-and-deprecated-objects
```

#### Getting software

Because software are the union of two STIX types (`tool` and `malware`), the process for accessing software is slightly more complicated.

```python
from itertools import chain
from stix2 import Filter

def get_software(thesrc):
    return list(chain.from_iterable(
        thesrc.query(f) for f in [
            Filter("type", "=", "tool"),
            Filter("type", "=", "malware")
        ]
    ))

get_software(src)
```

### Objects by content

Sometimes it may be useful to query objects by the content of their description:

```python
from stix2 import Filter

def get_techniques_by_content(thesrc, content):
    techniques = src.query([ Filter('type', '=', 'attack-pattern') ])
    return list(filter(lambda t: content.lower() in t.description.lower(), techniques))

# Get all techniques where the string LSASS appears in the description
get_techniques_by_content(src, 'LSASS')
```

### Techniques by platform

Techniques are associated with one or more platforms. You can query the techniques
under a specific platform with the following code:

```python
from stix2 import Filter

def get_techniques_by_platform(thesrc, platform):
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_platforms', '=', platform)
    ])

# get techniques in the windows platform
get_techniques_by_platform(src, 'Windows')
```

### Techniques by tactic

Techniques are related to tactics by their kill_chain_phases property.
The `phase_name` of each kill chain phase corresponds to the `x_mitre_shortname` of a tactic.

```python
from stix2 import Filter

def get_tactic_techniques(thesrc, tactic):
    # double checking the kill chain is MITRE ATT&CK
    # note: kill_chain_name is different for other domains:
    #    - enterprise: "mitre-attack"
    #    - mobile: "mitre-mobile-attack"
    #    - ics: "mitre-ics-attack"
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])


# use the x_mitre_shortname as argument
get_tactic_techniques(src, 'defense-evasion')
```

### Tactics by matrix

The tactics are individual objects (`x-mitre-tactic`), and their order in a matrix (`x-mitre-matrix`) is
found within the `tactic_refs` property in a matrix. The order of the tactics in that list matches
the ordering of the tactics in that matrix. The following recipe returns a structured list of tactics within each matrix of the input DataStore.

```python
from stix2 import Filter

def getTacticsByMatrix(thesrc):
    tactics = {}
    matrix = thesrc.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])

    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(thesrc.get(tactic_id))

    return tactics

# get tactic layout
getTacticsByMatrix(src)
```

### Objects created or modified since a given date

Sometimes you may want to get a list of objects which have been created or modified after a certain time.
This code could be used within a larger function or script to alert when a new object
has been added to the ATT&CK catalog.

```python
from stix2 import Filter

def get_created_after(thesrc, timestamp):
    filt = [
        Filter('created', '>', timestamp)
    ]
    return thesrc.query(filt)

get_created_after(src, "2018-10-01T00:14:20.652Z")


def get_modified_after(thesrc, timestamp):
    filt = [
        Filter('modified', '>', timestamp)
    ]
    return thesrc.query(filt)

get_modified_after(src, "2018-10-01T00:14:20.652Z")
```

## Getting related objects

A large part of working with ATT&CK revolves around parsing relationships between objects. It is useful
to track not only the related object but the relationship itself because a description is often
present to contextualize the nature of the relationship. The following recipes demonstrate
some common uses of relationships.

### Relationships microlibrary

The following microlibrary can be used to build a lookup table of stixID to related objects and relationships.
The argument to each accessor function is a STIX2 MemoryStore to build the relationship mappings from.

```python
from pprint import pprint
from stix2 import MemoryStore, Filter

# See section below on "Removing revoked and deprecated objects"
def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
    ])

    # See section below on "Removing revoked and deprecated objects"
    relationships = remove_revoked_deprecated(relationships)

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}

    # build the dict
    for relationship in relationships:
        if src_type in relationship.source_ref and target_type in relationship.target_ref:
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output

# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group and each software used by campaigns attributed to the group."""
    # get all software used by groups
    tools_used_by_group = get_related(thesrc, "intrusion-set", "uses", "tool")
    malware_used_by_group = get_related(thesrc, "intrusion-set", "uses", "malware")
    software_used_by_group = {**tools_used_by_group, **malware_used_by_group} # group_id -> {software, relationship}

    # get groups attributing to campaigns and all software used by campaigns
    software_used_by_campaign = get_related(thesrc, "campaign", "uses", "tool")
    malware_used_by_campaign = get_related(thesrc, "campaign", "uses", "malware")
    for id in malware_used_by_campaign:
        if id in software_used_by_campaign:
            software_used_by_campaign[id].extend(malware_used_by_campaign[id])
        else:
            software_used_by_campaign[id] = malware_used_by_campaign[id]
    campaigns_attributed_to_group = {
        "campaigns": get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
        "software": software_used_by_campaign # campaign_id => {software, relationship}
    }

    for group_id in campaigns_attributed_to_group["campaigns"]:
        software_used_by_campaigns = []
        # check if attributed campaign is using software
        for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in campaigns_attributed_to_group["software"]:
                software_used_by_campaigns.extend(campaigns_attributed_to_group["software"][campaign_id])
        
        # update software used by group to include software used by a groups attributed campaign
        if group_id in software_used_by_group:
            software_used_by_group[group_id].extend(software_used_by_campaigns)
        else:
            software_used_by_group[group_id] = software_used_by_campaigns
    return software_used_by_group

def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software and each software used by attributed campaigns."""
    # get all groups using software
    groups_using_tool = get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True)
    groups_using_malware = get_related(thesrc, "intrusion-set", "uses", "malware", reverse=True)
    groups_using_software = {**groups_using_tool, **groups_using_malware} # software_id => {group, relationship}

    # get campaigns attributed to groups and all campaigns using software
    campaigns_using_software = get_related(thesrc, "campaign", "uses", "tool", reverse=True)
    campaigns_using_malware = get_related(thesrc, "campaign", "uses", "malware", reverse=True)
    for id in campaigns_using_malware:
        if id in campaigns_using_software:
            campaigns_using_software[id].extend(campaigns_using_malware[id])
        else:
            campaigns_using_software[id] = campaigns_using_malware[id]
    groups_attributing_to_campaigns = {
        "campaigns": campaigns_using_software,# software_id => {campaign, relationship}
        "groups": get_related(thesrc, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
    }

    for software_id in groups_attributing_to_campaigns["campaigns"]:
        groups_attributed_to_campaigns = []
        # check if campaign is attributed to group
        for campaign in groups_attributing_to_campaigns["campaigns"][software_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in groups_attributing_to_campaigns["groups"]:
                groups_attributed_to_campaigns.extend(groups_attributing_to_campaigns["groups"][campaign_id])
        
        # update groups using software to include software used by a groups attributed campaign
        if software_id in groups_using_software:
            groups_using_software[software_id].extend(groups_attributed_to_campaigns)
        else:
            groups_using_software[software_id] = groups_attributed_to_campaigns
    return groups_using_software

# software:campaign
def software_used_by_campaigns(thesrc):
    """returns campaign_id => {software, relationship} for each software used by the campaign."""
    tools_used_by_campaign = get_related(thesrc, "campaign", "uses", "tool")
    malware_used_by_campaign = get_related(thesrc, "campaign", "uses", "malware")
    return {**tools_used_by_campaign, **malware_used_by_campaign}

def campaigns_using_software(thesrc):
    """returns software_id => {campaign, relationship} for each campaign using the software."""
    campaigns_using_tool = get_related(thesrc, "campaign", "uses", "tool", reverse=True)
    campaigns_using_malware = get_related(thesrc, "campaign", "uses", "malware", reverse=True)
    return {**campaigns_using_tool, **campaigns_using_malware}

# campaign:group
def groups_attributing_to_campaign(thesrc):
    """returns campaign_id => {group, relationship} for each group attributing to the campaign."""
    return get_related(thesrc, "campaign", "attributed-to", "intrusion-set")

def campaigns_attributed_to_group(thesrc):
    """returns group_id => {campaign, relationship} for each campaign attributed to the group."""
    return get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True)

# technique:group
def techniques_used_by_groups(thesrc):
    """returns group_id => {technique, relationship} for each technique used by the group and each
       technique used by campaigns attributed to the group."""
    # get all techniques used by groups
    techniques_used_by_groups = get_related(thesrc, "intrusion-set", "uses", "attack-pattern") # group_id => {technique, relationship}

    # get groups attributing to campaigns and all techniques used by campaigns
    campaigns_attributed_to_group = {
        "campaigns": get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
        "techniques": get_related(thesrc, "campaign", "uses", "attack-pattern") # campaign_id => {technique, relationship}
    }

    for group_id in campaigns_attributed_to_group["campaigns"]:
        techniques_used_by_campaigns = []
        # check if attributed campaign is using technique
        for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in campaigns_attributed_to_group["techniques"]:
                techniques_used_by_campaigns.extend(campaigns_attributed_to_group["techniques"][campaign_id])

        # update techniques used by groups to include techniques used by a groups attributed campaign
        if group_id in techniques_used_by_groups:
            techniques_used_by_groups[group_id].extend(techniques_used_by_campaigns)
        else:
            techniques_used_by_groups[group_id] = techniques_used_by_campaigns
    return techniques_used_by_groups

def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique and each campaign attributed to groups using the technique."""
    # get all groups using techniques
    groups_using_techniques = get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True) # technique_id => {group, relationship}

    # get campaigns attributed to groups and all campaigns using techniques
    groups_attributing_to_campaigns = {
        "campaigns": get_related(thesrc, "campaign", "uses", "attack-pattern", reverse=True), # technique_id => {campaign, relationship}
        "groups": get_related(thesrc, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
    }

    for technique_id in groups_attributing_to_campaigns["campaigns"]:
        campaigns_attributed_to_group = []
        # check if campaign is attributed to group
        for campaign in groups_attributing_to_campaigns["campaigns"][technique_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in groups_attributing_to_campaigns["groups"]:
                campaigns_attributed_to_group.extend(groups_attributing_to_campaigns["groups"][campaign_id])
        
        # update groups using techniques to include techniques used by a groups attributed campaign
        if technique_id in groups_using_techniques:
            groups_using_techniques[technique_id].extend(campaigns_attributed_to_group)
        else:
            groups_using_techniques[technique_id] = campaigns_attributed_to_group
    return groups_using_techniques

# technique:campaign
def techniques_used_by_campaigns(thesrc):
    """returns campaign_id => {technique, relationship} for each technique used by the campaign."""
    return get_related(thesrc, "campaign", "uses", "attack-pattern")

def campaigns_using_technique(thesrc):
    """returns technique_id => {campaign, relationship} for each campaign using the technique."""
    return get_related(thesrc, "campaign", "uses", "attack-pattern", reverse=True)

# technique:software
def techniques_used_by_software(thesrc):
    """return software_id => {technique, relationship} for each technique used by the software."""
    techniques_by_tool = get_related(thesrc, "tool", "uses", "attack-pattern")
    techniques_by_malware = get_related(thesrc, "malware", "uses", "attack-pattern")
    return {**techniques_by_tool, **techniques_by_malware}

def software_using_technique(thesrc):
    """return technique_id  => {software, relationship} for each software using the technique."""
    tools_by_technique_id = get_related(thesrc, "tool", "uses", "attack-pattern", reverse=True)
    malware_by_technique_id = get_related(thesrc, "malware", "uses", "attack-pattern", reverse=True)
    return {**tools_by_technique_id, **malware_by_technique_id}

# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)

def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)

# technique:sub-technique
def subtechniques_of(thesrc):
    """return technique_id => {subtechnique, relationship} for each subtechnique of the technique."""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)

def parent_technique_of(thesrc):
    """return subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique"""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern")[0]

# detectionstrategy:technique
def detectionstrategy_detects_techniques(thesrc):
    """return detectionstrategy_id => {technique, relationship} describing the detections of each detection strategy"""
    return get_related(thesrc, "x-mitre-detection-strategy", "detects", "attack-pattern")

def technique_detected_by_detectionstrategies(thesrc):
    """return technique_id => {detectionstrategy, relationship} describing the detection strategies that can detect the technique"""
    return get_related(thesrc, "x-mitre-detection-strategy", "detects", "attack-pattern", reverse=True)

# Example usage:
src = MemoryStore()
src.load_from_file("path/to/enterprise-attack.json")

group_id_to_software = software_used_by_groups(src)
pprint(group_id_to_software["intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050"])  # G0019
# [
#     {
#         "object": Malware, # S0061
#         "relationship": Relationship # relationship between G0019 and S0061
#     },
#     {
#         ...
#     }
# ]
```

### Getting techniques used by a group's software

Because a group uses software, and software uses techniques, groups can be considered indirect users of techniques used by their software.
These techniques are oftentimes distinct from the techniques used directly by a group, although there are occasionally intersections in these two sets of techniques.

The following recipe can be used to retrieve the techniques used by a group's software:

```python
from stix2.utils import get_type_from_id
from stix2 import Filter

def get_techniques_by_group_software(thesrc, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

get_techniques_by_group_software(src, "intrusion-set--f047ee18-7985-4946-8bfb-4ed754d3a0dd")
```

## Working with deprecated and revoked objects

Objects that are deemed no longer beneficial to track as part of the knowledge base are marked as deprecated,
and objects which are replaced by a different object are revoked.
In both cases, the old object is marked with a field (either `x_mitre_deprecated` or `revoked`) noting their status.
In the case of revoked objects, a relationship of type `revoked-by` is also created targeting the replacing object.

### Removing revoked and deprecated objects

Revoked and deprecated objects are kept in the knowledge base so that workflows relying on those objects are not
broken. We recommend you filter out revoked and deprecated objects from your views whenever possible since they are no
longer maintained by ATT&CK.

Revoked and deprecated objects can be removed quite easily:

```python
from stix2 import Filter

def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

mitigations = src.query([ Filter("type", "=", "course-of-action") ])
mitigations = remove_revoked_deprecated(mitigations)
```

### Getting a revoking object

When an object is replaced by another object, it is marked with the field `revoked` and a relationship of type `revoked-by`
is created where the `source_ref` is the revoked object and the `target_ref` is the revoking object.
This relationship can be followed to find the replacing object:

```python
from stix2 import Filter

def getRevokedBy(stix_id, thesrc):
    relations = thesrc.relationships(stix_id, 'revoked-by', source_only=True)
    revoked_by = thesrc.query([
        Filter('id', 'in', [r.target_ref for r in relations]),
        Filter('revoked', '=', False)
    ])
    if revoked_by is not None:
        revoked_by = revoked_by[0]

    return revoked_by

getRevokedBy("attack-pattern--c16e5409-ee53-4d79-afdc-4099dc9292df", src)
```
