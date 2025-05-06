import argparse
import os
from tqdm import tqdm
import json
from dateutil.parser import isoparse
import re


def stix_representation(timestamp):
    """Returns a string containing a STIX compatible representation of the input timestamp

    :param datetime timestamp:
    """
    return timestamp.isoformat(timespec='milliseconds')[:-6] + "Z"


def generate_collection_index(name, description, root_url, collection_index_id, folders):
    """Generates a collection index from the input data and returns the index as a dictionary

    :param str name: The name of the collection index
    :param str description: The description of the collection index
    :param str root_url: The root URL where the collections can be found; collection file paths will be appended to this to create the collection URL
    :param str collection_index_id: the id to assign to the collection index
    :param list of str folders: List of folders containing the collection JSON files to include in the index; cannot be used with files argument; will only match collections that end with a version number
    """
    version_regex = re.compile("(\w+-)+(\d\.?)+(-beta)?.json")
    files = []
    for folder in folders:
        files += list(map(lambda fname: os.path.join(folder, fname), filter(lambda fname: version_regex.match(fname), os.listdir(folder))))

    index_created = None
    index_modified = None
    collections = {} # STIX ID -> collection object

    for collection_bundle_file in tqdm(files, desc="parsing collections"):
        with open(collection_bundle_file, "r") as f:
            bundle = json.load(f)
            for collection_version in filter(lambda x: x["type"] == "x-mitre-collection", bundle["objects"]):
                # parse collection
                if collection_version["id"] not in collections:
                    # create
                    collections[collection_version["id"]] = {
                        "id": collection_version["id"],
                        "created": collection_version["created"], # created is the same for all versions
                        "versions": []
                    }
                collection = collections[collection_version["id"]]

                # append this as a version
                collection["versions"].append({
                    "version": collection_version["x_mitre_version"],
                    "url": root_url + collection_bundle_file if root_url.endswith("/") else root_url + "/" + collection_bundle_file,
                    "modified": collection_version["modified"],
                    "name": collection_version["name"], # this will be deleted later in the code
                    "description": collection_version["description"], # this will be deleted later in the code
                })
                # ensure the versions are ordered
                collection["versions"].sort(key=lambda version: isoparse(version["modified"]), reverse=True)

    for collection in collections.values():
        # set collection name and description from most recently modified version
        collection["name"] = collection["versions"][-1]["name"]
        collection["description"] = collection["versions"][-1]["description"]
        # set index created date according to first created collection
        index_created = index_created if index_created and index_created < isoparse(collection["created"]) else isoparse(collection["created"])
        # delete name and description from all versions
        for version in collection["versions"]:
            # set index created date according to first created collection
            index_modified = index_modified if index_modified and index_modified > isoparse(version["modified"]) else isoparse(version["modified"])
            # delete name and description from version since they aren't used in the output
            del version["name"]
            del version["description"]

    return {
        "id": collection_index_id,
        "name": name,
        "description": description,
        "created": stix_representation(index_created),
        "modified": stix_representation(index_modified),
        "collections": list(collections.values())
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a collection index from a set of collections."
    )
    parser.add_argument(
        "-name",
        type=str,
        default="MITRE ATT&CK",
        help="The name of the collection index (default: MITRE ATT&CK)"
    )
    parser.add_argument(
        "-description",
        type=str,
        default="MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.",
        help="The description of the collection index (default: standard text)"
    )
    parser.add_argument(
        "-root_url",
        type=str,
        default="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/",
        help="The root URL where the collections can be found (default: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/)"
    )
    parser.add_argument(
        "-output",
        type=str,
        default="index.json",
        help="The filename for the output collection index file (default: index.json)"
    )
    parser.add_argument(
        "-collection-index-id",
        type=str,
        default="10296991-439b-4202-90a3-e38812613ad4",
        help="A unique identifier for the collection index. (default: 10296991-439b-4202-90a3-e38812613ad4)"
    )
    parser.add_argument(
        '-folders',
        type=str,
        nargs="+",
        default=['enterprise-attack', 'mobile-attack', 'ics-attack'],
        help="folder of JSON files to treat as collections (default: ['enterprise-attack', 'mobile-attack', 'ics-attack'])"
    )

    args = parser.parse_args()
    output_file = args.output
    with open(output_file, "w") as f:
        options = vars(args)
        del options["output"]
        index = generate_collection_index(**options)
        print(f"writing to {output_file}")
        json.dump(index, f, indent=4)
