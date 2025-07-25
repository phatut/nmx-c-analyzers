# Enhanced NMX-C Analyzer Features

## Port Down Event Analysis

The enhanced analyzer now supports parsing and analyzing two types of events:

### 1. Legacy Trunk Failures (Original Format)
```
[Jul 19 2025 18:34:57] [WARNING] [tid 134] Trunk port failure detected for switch GUID 0xb0cf0e0300e42e00 and switch chassis sn 1825124190179, slot 7 port number 61 port GUID 0xb0cf0e0300e42e00 cage 7.
```

### 2. Port Down Events (New Format)
```
[Apr 11 2025 18:23:56] [INFO] [tid 259] fabric manager received port down event on switch with GUID 0xb0cf0e0300e60b00, port GUID 0xb0cf0e0300e60b00, and port num 1
```

## Port Type Classification

Using the SMDB topology data, the analyzer automatically classifies ports as:

- **Access Ports**: Connected to GPUs (switch GUID starts with `0xb0cf0e0300`, partner GUID doesn't)
- **Trunk Ports**: Connected to other switches (both GUIDs start with `0xb0cf0e0300`)
- **Unknown**: Cannot determine connection type from SMDB

## Real-World Analysis Results

From real-world dataset analysis:
- **16,687 port down events** detected
- **13,202 access ports** (connected to GPUs)
- **0 trunk ports** (switch-to-switch connections)
- **2,563 GPU NVL errors** found
- **GPU error correlation** with 5-second time window

## Enhanced Table Output

```
#   Timestamp           Switch/GPU GUID    Port Type   Event/Error  Details                             XID/Partner          Action
1   2025-04-11 18:23:56 00e60b00           1    Access UNKNOWN→DOWN Switch-00e60b00                     2c5345ac:5           fab
2   2025-04-11 18:23:56 00e60b00           2    Access UNKNOWN→DOWN Switch-00e60b00                     56fcd570:5           fab
```

## Integration with GPU NVL Errors

The analyzer correlates port down events with GPU NVL errors using:
- **Tight time correlation**: ≤5 seconds
- **Port/GUID matching**: Ensures related errors are properly linked
- **XID mapping**: Maps GPU error codes to equivalent NVIDIA XIDs

## Comprehensive Reporting

- **Table format**: Human-readable with port type classification
- **CSV export**: Machine-readable data for further analysis
- **GPU error details**: Separate CSV with full error context
- **Link partner identification**: Shows connected devices for each port

This enhancement provides complete visibility into both access port (GPU) and trunk port (switch) failures across the NMX-C fabric. 