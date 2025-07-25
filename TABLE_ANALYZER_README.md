# NMX-C Table Analyzer

Creates clean table format reports for trunk link failures with intelligent link partner correlation using SMDB data.

## Key Features

✅ **Table Format Reports**: Clean, readable table layout with abbreviated GUIDs and switch names  
✅ **Link Partner Correlation**: Uses SMDB dump to find connected link partners  
✅ **Partner Grouping**: Groups link partners in consecutive rows for easy analysis  
✅ **Same Timestamp Detection**: Finds simultaneous failures on both ends of trunk links  
✅ **CSV Export**: Detailed data for further analysis  
✅ **Auto-Discovery**: Works with standard nmx-c directory structure  

## Quick Start

```bash
# Basic table report
python3 nmx_table_analyzer.py

# Custom output with CSV
python3 nmx_table_analyzer.py -o my_trunk_report.txt -c detailed_data.csv
```

## Sample Output

```
TRUNK LINK FAILURES REPORT
========================================================================================================================

#   Timestamp           Switch GUID        Port Cage State Change Switch Name                         Partner              Sources        
------------------------------------------------------------------------------------------------------------------------
1   2025-07-19 18:34:57 00e31440           61   7    ACTIVE→DOWN  gb-nvl-087-switch03:N5110_LD        00e42e00:61          fab/nvl        

2   2025-07-22 11:22:25 00e31520           54   5    INIT→DOWN    gb-nvl-087-switch04:N5110_LD        00df4460:54          fab/nvl        
    2025-07-22 11:22:25 00df4460           54   5    INIT→DOWN    gb-nvl-085-switch04:N5110_LD        00e31520:54          fab/nvl        

3   2025-07-24 14:54:53 00e42e60           70   9    ACTIVE→DOWN  gb-nvl-085-switch02:N5110_LD        00e314a0:70          fab/nvl        
    2025-07-24 14:54:53 00e314a0           70   9    ACTIVE→DOWN  gb-nvl-087-switch02:N5110_LD        00e42e60:70          fab/nvl        

========================================================================================================================
SUMMARY: 16 events in 3 incidents
Link partners identified: 16/16 events
```

## What It Shows

### Table Columns
- **#**: Incident number (grouped link partners share same number)
- **Timestamp**: When the failure occurred
- **Switch GUID**: Last 8 chars of switch GUID for clarity
- **Port**: Port number that failed
- **Cage**: Physical cage number
- **State Change**: What happened (ACTIVE→DOWN, INIT→DOWN, etc.)
- **Switch Name**: Abbreviated switch name
- **Partner**: Link partner GUID:Port if found in SMDB
- **Sources**: Abbreviated source files (fab/nvl = fabricmanager/nvlsm)

### Link Partner Intelligence
- **Finds Connections**: Uses SMDB dump to identify which ports are connected
- **Groups Partners**: Link partners appear in consecutive rows
- **Same Incident**: Partners that fail simultaneously get the same incident number
- **Timestamp Correlation**: Matches events within 5 seconds as likely partners

## Requirements

- Standard nmx-c directory structure
- `dumps/nvlsm-smdb.dump.gz` file (for link partner correlation)
- `fabricmanager.log.gz` and `nvlsm.log.gz` files

## Command Options

```bash
python3 nmx_table_analyzer.py [options]

Options:
  -d, --nmx-dir DIR      nmx-c directory path (default: current)
  -o, --output FILE      Table report output file (default: trunk_failures_table.txt)  
  -c, --csv FILE         Generate CSV format report
  -m, --max-rotated NUM  Max rotated log files to process (default: 10)
  -t, --time-window SEC  Correlation time window (default: 10)
```

## Real-World Usage

### Daily Monitoring
```bash
# Add to daily cron job
cd /var/log/nmx-c/
python3 /tools/nmx_table_analyzer.py -o daily_trunk_failures.txt
```

### Incident Analysis
```bash
# Generate detailed reports for analysis
python3 nmx_table_analyzer.py \
  -o incident_report.txt \
  -c incident_data.csv \
  --time-window 15
```

### Multiple Sites
```bash
# Process multiple nmx-c directories
for site in site1 site2 site3; do
    python3 nmx_table_analyzer.py \
      --nmx-dir /logs/$site/nmx-c/ \
      -o "${site}_trunk_failures.txt"
done
```

## Example Analysis

Looking at the sample output above:
- **Incident 1**: Single-ended failure (partner not detected in timeframe)
- **Incident 2**: **Perfect link pair failure** - both ends failed simultaneously
- **Incident 3**: **Another perfect pair** - synchronized failure on connected ports

This pattern helps identify:
- True link failures (both ends fail together)
- Switch-specific issues (single-ended failures)
- Timing relationships between connected failures

## CSV Format

The CSV export includes all detailed fields for analysis:
- Full GUIDs, switch names, timestamps
- Partition IDs, TIDs, chassis serial numbers
- Link partner information
- Source file tracking

Perfect for importing into spreadsheets, databases, or analysis tools. 