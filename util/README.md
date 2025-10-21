# Utilities

This folder contains utilities for the maintenance of the data in this repository.
They are provided for maintainers within the ATT&CK team and to enable the ATT&CK community to release their own extensions of this dataset on similarly formatted repositories. 

## Requirements
- [python3](https://www.python.org/)

## Installation

1. Create virtual environment:
    - macOS and Linux: `python3 -m venv env`
    - Windows: `py -m venv env`
2. Activate the virtual environment:
    - macOS and Linux: `source env/bin/activate`
    - Windows: `env/Scripts/activate.bat`
3. Install requirements into the virtual environment: `pip3 install -r util/requirements.txt`

## [generate-collection-index.py](generate-collection-index.py)

This script generates a collection index from a set of collections. Run `python3 util/generate-collection-index.py -h` for usage instructions.

The [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) tool can create collections to serve as input to this script.

## [index-to-md.py](index-to-md.py)

This script transforms a machine readable collection index JSON file into a human readable Markdown file, providing a listing of the full contents of the collection index. Run `python3 util/index-to-md.py -h` for usage instructions.

## Additional Files

- [sample_3.3.0_stix-detection-strategy.json](./sample_3.3.0_stix-detection-strategy.json): A sample STIX file introducing the new Detection Strategy format using the [v3.3.0 ATT&CK Spec](https://mitre-attack.github.io/attack-data-model/).
