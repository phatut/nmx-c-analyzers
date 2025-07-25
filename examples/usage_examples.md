# Usage Examples

This directory contains sample outputs and usage patterns for the NMX-C analyzers.

## Sample Files

- `sample_table_report.txt` - Clean table format output from table analyzer
- `sample_csv_data.csv` - Detailed CSV data for analysis and importing

## Common Usage Patterns

### Daily Operations

```bash
# Quick daily check
cd /var/log/nmx-c/
python3 nmx_table_analyzer.py

# Automated daily report
#!/bin/bash
DATE=$(date +%Y%m%d)
cd /var/log/nmx-c/
python3 /tools/nmx_table_analyzer.py -o "daily_${DATE}.txt"
```

### Incident Response

```bash
# Generate both formats during incident
python3 nmx_table_analyzer.py \
  -o incident_table.txt \
  -c incident_data.csv

# Include comprehensive analysis
python3 nmx_analyzer.py \
  -o incident_detailed.txt \
  -j incident_full.json \
  --time-window 15
```

### Multi-Site Monitoring

```bash
# Process multiple sites
SITES="site1 site2 site3"
for site in $SITES; do
    echo "Processing $site..."
    python3 nmx_table_analyzer.py \
      --nmx-dir "/logs/${site}/nmx-c/" \
      -o "${site}_trunk_failures.txt" \
      -c "${site}_data.csv"
done

# Combine reports
cat *_trunk_failures.txt > combined_report.txt
```

### Historical Analysis

```bash
# Process rotated logs for trends
python3 nmx_analyzer.py \
  --max-rotated 30 \
  -o historical_analysis.txt \
  -j historical_data.json

# Limited time window for specific analysis
python3 nmx_table_analyzer.py \
  --time-window 5 \
  -o precise_correlation.txt
```

### Remote Analysis

```bash
# Analyze remote nmx-c directory
python3 nmx_table_analyzer.py \
  --nmx-dir /mnt/remote/logs/nmx-c/ \
  -o remote_analysis.txt

# Process via SSH
ssh server1 "cd /var/log/nmx-c && python3 nmx_table_analyzer.py" > server1_report.txt
```

### Cron Integration

```bash
# /etc/cron.d/nmx-analysis
# Daily at 6 AM
0 6 * * * root cd /var/log/nmx-c && python3 /usr/local/bin/nmx_table_analyzer.py -o /reports/daily_$(date +\%Y\%m\%d).txt

# Hourly during business hours
0 9-17 * * 1-5 ops cd /var/log/nmx-c && python3 /usr/local/bin/nmx_table_analyzer.py -o /tmp/hourly_check.txt
```

### Advanced Filtering

```bash
# Focus on specific time periods (modify script as needed)
python3 nmx_table_analyzer.py \
  --time-window 2 \
  -o precise_timing.txt

# Process only recent rotated files
python3 nmx_table_analyzer.py \
  --max-rotated 3 \
  -o recent_analysis.txt
```

## Output Interpretation

### Table Report Format
```
#   Timestamp           Switch GUID        Port Cage State Change Switch Name                         Partner              
------------------------------------------------------------------------------------------------------------------------
1   2025-07-19 18:34:57 00e31440           61   7    ACTIVE→DOWN  gb-nvl-087-switch03:N5110_LD        00e42e00:61          
```

**Key Points:**
- **#**: Incident number (same number = related failures)
- **Switch GUID**: Last 8 characters for readability
- **State Change**: Shows what happened (ACTIVE→DOWN, INIT→DOWN, etc.)
- **Partner**: Connected switch:port if found in SMDB

### CSV Data Analysis
The CSV contains full details suitable for:
- Spreadsheet analysis
- Database imports
- Statistical analysis
- Trend identification

### Link Partner Correlation
When you see consecutive rows with the same incident number:
```
2   2025-07-22 11:22:25 00e31520           54   5    INIT→DOWN    gb-nvl-087-switch04:N5110_LD        00df4460:54          
    2025-07-22 11:22:25 00df4460           54   5    INIT→DOWN    gb-nvl-085-switch04:N5110_LD        00e31520:54          
```

This indicates **synchronized failure** on both ends of a trunk link - a true link failure rather than switch-specific issue.

## Performance Tips

- Use table analyzer for quick daily checks
- Use comprehensive analyzer for detailed investigations
- Limit `--max-rotated` for faster processing on busy systems
- Run during low-activity periods for large historical analysis 