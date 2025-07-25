# NMX-C Directory Structure

This document explains the expected directory structure for NMX-C fabric systems that the analyzers work with.

## Standard Layout

```
nmx-c/
├── fabricmanager.log.gz          # Primary fabric manager log
├── fabricmanager.log.1.gz        # Previous rotation
├── fabricmanager.log.2.gz        # Older rotation (pattern continues)
├── nvlsm.log.gz                  # Primary nvlSM log  
├── nvlsm.log.1.gz                # Previous rotation
├── nvlsm.log.2.gz                # Older rotation (pattern continues)
├── dumps/                        # Dump files directory
│   ├── nvlsm-activity.dump.gz    # Activity dump
│   ├── nvlsm-smdb.dump.gz        # **SMDB dump (critical for link correlation)**
│   ├── nvlsm-perflog.json.gz     # Performance logs
│   ├── nvlsm-statistics.dump.gz  # Statistics
│   ├── nvlsm-routers.dump.gz     # Router information
│   └── nvlsm-virtualization.dump.gz
├── nvlsm/                        # nvlSM data files
│   ├── guid2alid.gz              # GUID to ALID mapping
│   ├── guid2lid.gz               # GUID to LID mapping
│   ├── neighbors.gz              # Neighbor relationships
│   ├── port2nvl_prtn.gz          # Port to partition mapping
│   └── [additional mapping files]
├── fib.log.gz                    # FIB (Forwarding Information Base) log
├── gwapi.log.gz                  # Gateway API log
├── rest.log.gz                   # REST API log
└── supervisord.log.gz            # Supervisor daemon log
```

## Critical Files for Analysis

### Primary Analysis Files
- **`fabricmanager.log.gz`** - Contains trunk port failure events
- **`nvlsm.log.gz`** - Contains link state change events
- **`dumps/nvlsm-smdb.dump.gz`** - Contains link topology for partner correlation

### Log Rotation Pattern
- `.log.gz` - Most recent log
- `.log.1.gz` - Previous rotation  
- `.log.2.gz` - Older rotation
- Pattern continues with incrementing numbers

## File Descriptions

### Fabric Manager Logs
Contains critical events including:
- Trunk port failures
- Link failure events  
- Partition notifications
- Switch discovery
- Error conditions

**Sample Entry:**
```
[Jul 19 2025 18:34:57] [WARNING] [tid 134] Trunk port failure detected for switch GUID 0xb0cf0e0300e42e00 and switch chassis sn 1825124190179, slot 7 port number 61 port GUID 0xb0cf0e0300e42e00 cage 7.
```

### nvlSM Logs  
Contains subnet manager events including:
- Port state changes
- Link up/down events
- Discovery processes
- Routing updates

**Sample Entry:**
```
Jul 19 18:34:55 896261 [85BA8640] 0x02 -> osm_spst_rcv_process: Switch 0xb0cf0e0300e31440 MF0;gb-nvl-087-switch03:N5110_LD/U1 port 61 (sw7p1s1) changed state from ACTIVE to DOWN
```

### SMDB Dump (Critical)
Contains complete fabric topology including:
- Switch-to-switch connections  
- Port-to-port mappings
- Link partner relationships
- Network topology graph

**Sample Entry:**
```
NodeGUID1, PortNum1, NodeGUID2, PortNum2
0xb0cf0e0300e31440, 61, 0xb0cf0e0300e42e00, 61
```

## Validation Requirements

The analyzers validate directory structure by checking for:
1. At least one primary log file (`fabricmanager.log.gz` OR `nvlsm.log.gz`)
2. At least one additional indicator (`dumps/` OR `nvlsm/` directory)

## Directory Location Examples

### Common Paths
- `/var/log/nmx-c/`
- `/logs/nmx-c/`  
- `/data/logs/site1/nmx-c/`
- `/mnt/shared/logs/nmx-c/`

### Multi-Site Structure
```
/logs/
├── site1/
│   └── nmx-c/
│       ├── fabricmanager.log.gz
│       └── [standard structure]
├── site2/
│   └── nmx-c/
│       ├── fabricmanager.log.gz  
│       └── [standard structure]
└── site3/
    └── nmx-c/
        ├── fabricmanager.log.gz
        └── [standard structure]
```

## Permissions

Ensure read access to:
- All `.log.gz` files
- `dumps/` directory and contents
- `nvlsm/` directory and contents

## File Sizes

Typical file sizes:
- `fabricmanager.log.gz`: 10-100MB
- `nvlsm.log.gz`: 50-500MB  
- `nvlsm-smdb.dump.gz`: 1-10MB
- Rotated files: Similar to primary logs

## Troubleshooting

### Common Issues
- **Missing SMDB dump**: Link partner correlation will be disabled
- **No rotated files**: Only current logs will be processed
- **Permission errors**: Ensure read access to all files
- **Incomplete structure**: Analyzer will warn but attempt to continue

### Verification Commands
```bash
# Check structure
ls -la *.log.gz dumps/ nvlsm/

# Verify file access
gzcat fabricmanager.log.gz | head -5
gzcat nvlsm.log.gz | head -5
gzcat dumps/nvlsm-smdb.dump.gz | head -10

# Check rotated files
ls -la *.log.*.gz
``` 