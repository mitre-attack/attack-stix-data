"""Convert STIX bundle to FileSystemStore"""
import argparse
import os
import errno
import uuid
import shutil
import json


def bundle_to_filesystem(bundle_path):
    """
    convert a single STIX bundle into a FileSystemSource. Output FileSystemSource will be created in the same folder as the given bundle
    """
    
    print(f'Converting bundle to FileSystemSource: {bundle_path}')

    output_dir = os.path.join(*bundle_path.split("/")[:-1])

    with open(bundle_path) as f:
        bundle = json.load(f)

    object_types = ['attack-pattern', 'relationship', 'course-of-action', 'identity', 'intrusion-set', 'malware', 'tool', 'x-mitre-tactic', 'x-mitre-matrix', 'marking-definition', 'x-mitre-collection']
    stix_objects = {}
    for obj_type in object_types:
        stix_objects[obj_type] = []

    for obj in bundle['objects']:
        obj_type = obj['type']
        stix_objects[obj_type].append(obj)

    for obj_type in object_types:
        if stix_objects[obj_type]:
            print(f' - Creating bundles for {obj_type} objects')
            try:
                output_path = os.path.join(output_dir, obj_type)
                os.makedirs(output_path)
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise 
            for obj in stix_objects[obj_type]:
                stix = {}
                stix['type'] = 'bundle'
                stix['id'] = f'bundle--{uuid.uuid4()}'
                stix['spec_version'] = '2.0'
                stix['objects'] = [obj]

                with open(os.path.join(output_path, obj['id'] + '.json'), 'w') as f:
                    f.write(json.dumps(stix, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert STIX bundles to FileSystemSources. All outputs FileSystemSources will appear in the same folder as their corresponding input STIX bundle.')
    
    input_options = parser.add_mutually_exclusive_group(required=True) # require at least one input type
    input_options.add_argument(
        '-files',
        type=str,
        nargs="+",
        metavar=("bundle1", "bundle2"),
        help="Specify a Collection version bundle to convert into a FileSystemSource"
    )
    input_options.add_argument(
        '-folders',
        type=str,
        nargs="+",
        help="Specify a number of collection folders, and the collection version sub-folders will be converted into FileSystemSources"
    )

    args = parser.parse_args()
    if args.files:
        for bundle in args.files:
            bundle_to_filesystem(bundle)
    elif args.folders:
        for collection_folder in args.folders:
            for collection_folder_item in os.listdir(collection_folder):
                collection_folder_path = os.path.join(collection_folder, collection_folder_item)
                if os.path.isdir(collection_folder_path):
                    collection_version_folder = collection_folder_path
                    collection_version_items = filter(lambda collection_version_item: os.path.isfile(os.path.join(collection_version_folder, collection_version_item)), os.listdir(collection_version_folder))
                    collection_version_jsons = list(filter(lambda fname: fname.endswith(".json"), collection_version_items))
                    if len(collection_version_jsons) > 1:
                        print(f"More than one JSON object found in folder {collection_version_folder}:\n\t{collection_version_jsons}\n\t This folder will be skipped")
                    else:
                        bundle_to_filesystem(os.path.join(collection_version_folder, collection_version_jsons[0]))
    else:
        print("no output type selected")
