#!/usr/bin/env python3

import gzip
from pathlib import Path

# Debug NODES section parsing
smdb_file = '/Users/dwaxman/Downloads/flattened_nmx_c/nmx-c-11/dumps/nvlsm-smdb.dump.gz'

print("Debugging NODES section parsing...")

with gzip.open(smdb_file, 'rt', encoding='utf-8', errors='ignore') as f:
    content = f.read()

lines = content.split('\n')
in_nodes_section = False
nodes_count = 0
node_descriptions = {}

for i, line in enumerate(lines):
    line = line.strip()
    
    # Debug: look for NODES section
    if "SystemImageGUID, NodeGUID" in line:
        print(f"Found NODES header at line {i}: {line}")
        in_nodes_section = True
        continue
    elif in_nodes_section and line.startswith("0x"):
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 8:
            node_guid = parts[1]  # NodeGUID is the second field
            node_desc = parts[7].strip('"')  # NodeDesc is the 8th field, remove quotes
            node_descriptions[node_guid] = node_desc
            nodes_count += 1
            if nodes_count <= 3:  # Show first 3 for debugging
                print(f"  Parsed node {nodes_count}: {node_guid} -> {node_desc}")
    elif line.startswith("END_NODES") or (in_nodes_section and line.startswith("START_")):
        print(f"End of NODES section at line {i}: {line}")
        in_nodes_section = False

print(f"\nTotal nodes parsed: {nodes_count}")
print(f"Sample GUIDs: {list(node_descriptions.keys())[:5]}")

# Test specific GUIDs from the sample output
test_guids = ['0xb0cf0e0300e42e00', '0xb0cf0e0300e31440']
for guid in test_guids:
    desc = node_descriptions.get(guid, "NOT FOUND")
    print(f"Test {guid}: {desc}")
