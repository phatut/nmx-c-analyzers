#!/usr/bin/env python3

# Fix the SMDB parser by adding the working NODES parsing
import re

with open('nmx_table_analyzer.py', 'r') as f:
    content = f.read()

# Add nodes_count variable 
content = re.sub(
    r'(in_nodes_section = False\n            links_count = 0)',
    r'\1\n            nodes_count = 0',
    content
)

# Add NODES parsing before LINKS parsing
nodes_parsing = '''                # Parse NODES section for descriptions
                if line == "SystemImageGUID, NodeGUID, NodeType, ExtNodeType, NumPorts, VendorID, DeviceID, NodeDesc":
                    in_nodes_section = True
                    continue
                elif in_nodes_section and line.startswith("0x"):
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 8:
                        node_guid = parts[1]  # NodeGUID is the second field
                        node_desc = parts[7].strip('"')  # NodeDesc is the 8th field, remove quotes
                        self.node_descriptions[node_guid] = node_desc
                        nodes_count += 1
                elif line.startswith("END_NODES") or (in_nodes_section and line.startswith("START_")):
                    in_nodes_section = False
                
                # Parse LINKS section
                el'''

content = re.sub(
    r'(                if line == "NodeGUID1, PortNum1, NodeGUID2, PortNum2":)',
    nodes_parsing + r'if line == "NodeGUID1, PortNum1, NodeGUID2, PortNum2":',
    content
)

# Update the print statement
content = re.sub(
    r'print\(f"Found \{links_count\} total links in SMDB"\)',
    r'print(f"Found {nodes_count} nodes and {links_count} total links in SMDB")',
    content
)

with open('nmx_table_analyzer.py', 'w') as f:
    f.write(content)

print("✅ Fixed SMDB parser with NODES parsing")
