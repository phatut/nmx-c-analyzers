# Documentation

Technical documentation for the NMX-C Fabric Analyzers.

## Documents

- **[nmx-c-structure.md](nmx-c-structure.md)** - Expected directory structure and file descriptions
- **[correlation-logic.md](correlation-logic.md)** - How event correlation works across different log sources

## Quick References

### File Requirements
- `fabricmanager.log.gz` - Trunk port failure events
- `nvlsm.log.gz` - Link state change events  
- `dumps/nvlsm-smdb.dump.gz` - Link topology (for partner correlation)

### Correlation Process
1. Parse fabric manager trunk failures
2. Parse nvlSM link state changes
3. Match events by GUID + Port + Time
4. Discover link partners from SMDB
5. Group partner events together

### Output Formats
- **Table Analyzer**: Clean table with partner grouping
- **Comprehensive Analyzer**: Detailed correlation analysis

## Getting Help

- Check [examples/](../examples/) for usage patterns
- Review sample outputs in examples directory
- See main [README.md](../README.md) for quick start guide
- Check [TABLE_ANALYZER_README.md](../TABLE_ANALYZER_README.md) for detailed table analyzer usage 