# Example Outputs

This directory contains sample outputs demonstrating the NMX-C analyzer capabilities.

## Table Format Examples

### `sample_table_with_gpu_errors.txt`
**NEW**: Shows the enhanced table format with GPU NVL error correlation
- Demonstrates GPU errors as indented sub-entries (├─)
- Shows tight correlation timing (GPU errors 2-3 seconds before trunk failures)
- Includes XID mapping and resolution recommendations
- Shows both link partner pairs and single-ended failures

### `sample_table_report.txt` 
**LEGACY**: Original table format without GPU error correlation
- Shows basic trunk failure detection and link partner grouping
- Useful for comparison with the enhanced format

## CSV Data Examples

### `sample_gpu_errors.csv`
**NEW**: Detailed GPU error data with trunk event correlation
- Complete GPU error information (error codes, subcodes, debug data)
- XID equivalents and resolution actions
- Trunk event context for each GPU error
- Machine-readable format for analysis tools

### `sample_csv_data.csv`
**LEGACY**: Basic trunk failure CSV data
- Shows standard trunk failure correlation without GPU data

## Input Data Examples

### `sample_input_logs.txt`
Shows what the raw log data looks like before analysis:
- Fabric Manager logs with GPU NVL errors and trunk failures
- nvlSM logs with link state changes
- SMDB dumps with link topology
- Explains the 6-step analysis process

## Quick Comparison

| File | Format | GPU Errors | Use Case |
|------|--------|------------|----------|
| `sample_table_with_gpu_errors.txt` | Table | Yes | Human reading, incident analysis |
| `sample_gpu_errors.csv` | CSV | Yes | Data analysis, correlation studies |
| `sample_table_report.txt` | Table | No | Legacy format reference |
| `sample_csv_data.csv` | CSV | No | Basic trunk failure data |

## How to Generate These

```bash
# Table format with GPU correlation
python3 nmx_table_analyzer.py -o trunk_report.txt

# CSV format with GPU error details
python3 nmx_table_analyzer.py -c analysis_data.csv
# This creates both analysis_data.csv and analysis_data_gpu_errors.csv

# Legacy comprehensive format
python3 nmx_analyzer.py -o detailed_report.txt -j analysis.json
```
