import argparse
import os
from tqdm import tqdm
import json
import uuid
from dateutil.parser import isoparse
import re

def generate_index(name, description, root_url, files=None, folders=None):
    """generate a collection index from the input data and return the index as a dict
    arguments:
        name (string): the name of the index
        description (string): the description of the index
        root_url (string): the root URL where the collections can be found. Specified collection paths will be appended to this for the collection URL
        files (string[], optional): collection JSON files to include in the index. Cannot be used with folder argument
        folder s(string[], optional): folders of collection JSON files to include in the index. Cannot be used with files argument. Will only match collections that end with a version number
        output (string, optional): filename for the generated collection index file
    """
    if (files and folders):
        print("cannot use both files and folder at the same time, please use only one argument at a time")
    
    if (folders):
        version_regex = re.compile("(\w+-)+(\d\.?)+.json")
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
                collection["versions"].sort(key=lambda version: isoparse(version["modified"]))

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
        "id": str(uuid.uuid4()),
        "name": name,
        "description": description,
        "created": index_created.isoformat(),
        "modified": index_modified.isoformat(),
        "collections": list(collections.values())
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
         description="Create a collection index from a set of collections"
    )
    parser.add_argument(
        "name",
        type=str,
        default=None,
        help="name of the collection index. If omitted a placeholder will be used"
    )
    parser.add_argument(
        "description",
        type=str,
        default=None,
        help="description of the collection index. If omitted a placeholder will be used"
    )
    parser.add_argument(
        "root_url",
        type=str,
        help="the root URL where the collections can be found. Specified collection paths will be appended to this for the collection URL"
    )
    parser.add_argument(
        "-output",
        type=str,
        default="index.json",
        help="filename for the output collection index file"
    )
    input_options = parser.add_mutually_exclusive_group(required=True) # require at least one input type
    input_options.add_argument(
        '-files',
        type=str,
        nargs="+",
        default=None,
        metavar=("collection1", "collection2"),
        help="list of collections to include in the index"
    )
    input_options.add_argument(
        '-folders',
        type=str,
        nargs="+",
        default=None,
        help="folder of JSON files to treat as collections"
    )

    args = parser.parse_args()
    # print(json.dumps(generate_index(args.name, args.description, args.root_url, files=args.files, folder=args.folder), indent=4))
    with open(args.output, "w") as f:
        index = generate_index(args.name, args.description, args.root_url, files=args.files, folders=args.folders)
        print(f"writing {args.output}")
        json.dump(index, f, indent=4)
