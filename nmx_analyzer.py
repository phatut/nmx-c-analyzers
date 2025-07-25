#!/usr/bin/env python3
"""
NMX-C Fabric Analysis Tool
Analyzes trunk port failures in fabric manager logs and correlates them with nvlSM link down events.
Designed to work with standard nmx-c directory structure with automatic log rotation discovery.
"""

import re
import gzip
import json
import glob
import os
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class TrunkPortFailure:
    """Represents a trunk port failure event from fabric manager logs"""
    timestamp: datetime
    switch_guid: str
    chassis_sn: str
    slot: int
    port_number: int
    port_guid: str
    cage: int
    partition_id: Optional[int] = None
    tid: Optional[int] = None
    source_file: Optional[str] = None


@dataclass
class LinkDownEvent:
    """Represents a link down event from nvlSM logs"""
    timestamp: datetime
    switch_guid: str
    switch_name: str
    port_number: int
    port_name: str
    state_from: str
    state_to: str
    thread_id: str
    source_file: Optional[str] = None


@dataclass
class CorrelatedEvent:
    """Represents a correlated trunk failure and link down event"""
    trunk_failure: TrunkPortFailure
    link_down: LinkDownEvent
    time_delta: timedelta
    correlation_confidence: str


class NMXAnalyzer:
    """Main analyzer class for NMX-C fabric events"""
    
    def __init__(self, nmx_directory: str = ".", max_rotated_files: int = 10):
        self.nmx_directory = Path(nmx_directory)
        self.max_rotated_files = max_rotated_files
        self.fabricmanager_logs: List[str] = []
        self.nvlsm_logs: List[str] = []
        self.trunk_failures: List[TrunkPortFailure] = []
        self.link_down_events: List[LinkDownEvent] = []
        self.correlations: List[CorrelatedEvent] = []
        
        # Auto-discover log files in nmx-c structure
        self._discover_nmx_files()
        
        # Regex patterns
        self.trunk_failure_pattern = re.compile(
            r'\[([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\] \[WARNING\] \[tid (\d+)\] '
            r'Trunk port failure detected for switch GUID (0x[a-fA-F0-9]+) and switch chassis sn (\d+), '
            r'slot (\d+) port number (\d+) port GUID (0x[a-fA-F0-9]+) cage (\d+)\.'
        )
        
        self.trunk_link_failure_pattern = re.compile(
            r'\[([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\] \[WARNING\] \[tid (\d+)\] '
            r'Detected a trunk link failure event for partition Id (\d+)\.'
        )
        
        self.link_down_pattern = re.compile(
            r'([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}) \d+ \[([A-Z0-9]+)\] 0x\d{2} -> '
            r'osm_(?:spst|pi)_rcv_process: Switch (0x[a-fA-F0-9]+) ([^;]+);([^:]+):([^/]+)/[^ ]+ '
            r'port (\d+)(?:\([^)]+\))? changed state from (\w+) to (\w+)'
        )

    def _verify_nmx_structure(self) -> bool:
        """Verify that we're in a valid nmx-c directory structure"""
        required_indicators = [
            'fabricmanager.log.gz',
            'nvlsm.log.gz', 
            'dumps',
            'nvlsm'
        ]
        
        found_indicators = []
        for indicator in required_indicators:
            if (self.nmx_directory / indicator).exists():
                found_indicators.append(indicator)
        
        return len(found_indicators) >= 2  # At least 2 indicators should be present

    def _discover_nmx_files(self):
        """Auto-discover all relevant log files in nmx-c directory structure"""
        print(f"Analyzing nmx-c directory: {self.nmx_directory.absolute()}")
        
        # Verify we're in the right structure
        if not self._verify_nmx_structure():
            print("WARNING: This doesn't appear to be a standard nmx-c directory structure")
            print("Expected files: fabricmanager.log.gz, nvlsm.log.gz, dumps/, nvlsm/")
        
        # Discover fabric manager logs (in root of nmx-c)
        fm_base = self.nmx_directory / "fabricmanager.log.gz"
        if fm_base.exists():
            self.fabricmanager_logs.append(str(fm_base))
        
        # Look for rotated fabric manager logs
        for i in range(1, self.max_rotated_files + 1):
            fm_rotated = self.nmx_directory / f"fabricmanager.log.{i}.gz"
            if fm_rotated.exists():
                self.fabricmanager_logs.append(str(fm_rotated))
        
        # Discover nvlsm logs (in root of nmx-c)
        nvlsm_base = self.nmx_directory / "nvlsm.log.gz"
        if nvlsm_base.exists():
            self.nvlsm_logs.append(str(nvlsm_base))
            
        # Look for rotated nvlsm logs
        for i in range(1, self.max_rotated_files + 1):
            nvlsm_rotated = self.nmx_directory / f"nvlsm.log.{i}.gz"
            if nvlsm_rotated.exists():
                self.nvlsm_logs.append(str(nvlsm_rotated))
        
        print(f"Found {len(self.fabricmanager_logs)} fabric manager log files: {[Path(f).name for f in self.fabricmanager_logs]}")
        print(f"Found {len(self.nvlsm_logs)} nvlsm log files: {[Path(f).name for f in self.nvlsm_logs]}")
        
        # Check for other interesting files
        self._report_additional_files()
        
        if not self.fabricmanager_logs:
            print("WARNING: No fabric manager log files found!")
        if not self.nvlsm_logs:
            print("WARNING: No nvlsm log files found!")

    def _report_additional_files(self):
        """Report other files available for analysis"""
        additional_logs = []
        
        # Check for other log files in root
        for log_pattern in ['*.log.gz', '*.log']:
            for log_file in self.nmx_directory.glob(log_pattern):
                if log_file.name not in [Path(f).name for f in self.fabricmanager_logs + self.nvlsm_logs]:
                    additional_logs.append(log_file.name)
        
        # Check dumps directory
        dumps_dir = self.nmx_directory / "dumps"
        if dumps_dir.exists():
            dump_files = list(dumps_dir.glob("*.gz")) + list(dumps_dir.glob("*.json*"))
            if dump_files:
                print(f"Found {len(dump_files)} dump files in dumps/: {[f.name for f in dump_files[:5]]}" + 
                      ("..." if len(dump_files) > 5 else ""))
        
        # Check nvlsm directory
        nvlsm_dir = self.nmx_directory / "nvlsm"
        if nvlsm_dir.exists():
            nvlsm_files = list(nvlsm_dir.glob("*.gz"))
            if nvlsm_files:
                print(f"Found {len(nvlsm_files)} nvlsm data files in nvlsm/: {[f.name for f in nvlsm_files[:5]]}" + 
                      ("..." if len(nvlsm_files) > 5 else ""))
        
        if additional_logs:
            print(f"Additional log files available: {additional_logs[:5]}" + 
                  ("..." if len(additional_logs) > 5 else ""))

    def parse_timestamp_fm(self, timestamp_str: str) -> datetime:
        """Parse fabric manager timestamp format: [Jul 19 2025 18:34:57]"""
        return datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
    
    def parse_timestamp_nvlsm(self, timestamp_str: str) -> datetime:
        """Parse nvlSM timestamp format: Jul 19 18:34:55"""
        # Add current year since it's missing
        return datetime.strptime(f"2025 {timestamp_str}", "%Y %b %d %H:%M:%S")

    def parse_fabricmanager_logs(self):
        """Parse fabric manager logs for trunk port failures"""
        print("Parsing fabric manager logs...")
        
        def read_lines_from_file(log_file):
            if log_file.endswith('.gz'):
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        yield line, Path(log_file).name
            else:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        yield line, Path(log_file).name
        
        current_partition_id = None
        
        # Process all fabric manager log files (newest first)
        for log_file in self.fabricmanager_logs:
            print(f"  Processing: {Path(log_file).name}")
            try:
                for line, source_file in read_lines_from_file(log_file):
                    # Check for trunk port failures
                    match = self.trunk_failure_pattern.search(line)
                    if match:
                        timestamp = self.parse_timestamp_fm(match.group(1))
                        tid = int(match.group(2))
                        switch_guid = match.group(3)
                        chassis_sn = match.group(4)
                        slot = int(match.group(5))
                        port_number = int(match.group(6))
                        port_guid = match.group(7)
                        cage = int(match.group(8))
                        
                        failure = TrunkPortFailure(
                            timestamp=timestamp,
                            switch_guid=switch_guid,
                            chassis_sn=chassis_sn,
                            slot=slot,
                            port_number=port_number,
                            port_guid=port_guid,
                            cage=cage,
                            partition_id=current_partition_id,
                            tid=tid,
                            source_file=source_file
                        )
                        self.trunk_failures.append(failure)
                        continue
                    
                    # Check for partition failure events
                    match = self.trunk_link_failure_pattern.search(line)
                    if match:
                        current_partition_id = int(match.group(3))
            except Exception as e:
                print(f"  Error processing {Path(log_file).name}: {e}")
        
        print(f"Found {len(self.trunk_failures)} trunk port failures across all files")

    def parse_nvlsm_logs(self):
        """Parse nvlSM logs for link down events"""
        print("Parsing nvlSM logs...")
        
        def read_lines_from_file(log_file):
            if log_file.endswith('.gz'):
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        yield line, Path(log_file).name
            else:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        yield line, Path(log_file).name
        
        # Process all nvlsm log files (newest first)
        for log_file in self.nvlsm_logs:
            print(f"  Processing: {Path(log_file).name}")
            try:
                for line, source_file in read_lines_from_file(log_file):
                    match = self.link_down_pattern.search(line)
                    if match and match.group(9) == "DOWN":
                        timestamp = self.parse_timestamp_nvlsm(match.group(1))
                        thread_id = match.group(2)
                        switch_guid = match.group(3)
                        switch_name = f"{match.group(4)};{match.group(5)}:{match.group(6)}"
                        port_number = int(match.group(7))
                        state_from = match.group(8)
                        state_to = match.group(9)
                        
                        link_event = LinkDownEvent(
                            timestamp=timestamp,
                            switch_guid=switch_guid,
                            switch_name=switch_name,
                            port_number=port_number,
                            port_name="",  # Could extract from port pattern if needed
                            state_from=state_from,
                            state_to=state_to,
                            thread_id=thread_id,
                            source_file=source_file
                        )
                        self.link_down_events.append(link_event)
            except Exception as e:
                print(f"  Error processing {Path(log_file).name}: {e}")
        
        print(f"Found {len(self.link_down_events)} link down events across all files")

    def correlate_events(self, time_window_seconds: int = 10):
        """Correlate trunk failures with link down events"""
        print("Correlating events...")
        
        for failure in self.trunk_failures:
            best_match = None
            best_confidence = "NONE"
            min_time_delta = None
            
            for link_event in self.link_down_events:
                # Check if GUID and port match
                if (failure.switch_guid.lower() == link_event.switch_guid.lower() and
                    failure.port_number == link_event.port_number):
                    
                    # Calculate time difference
                    time_delta = abs((failure.timestamp - link_event.timestamp).total_seconds())
                    
                    if time_delta <= time_window_seconds:
                        if min_time_delta is None or time_delta < min_time_delta:
                            min_time_delta = time_delta
                            best_match = link_event
                            if time_delta <= 2:
                                best_confidence = "HIGH"
                            elif time_delta <= 5:
                                best_confidence = "MEDIUM"
                            else:
                                best_confidence = "LOW"
            
            if best_match:
                correlation = CorrelatedEvent(
                    trunk_failure=failure,
                    link_down=best_match,
                    time_delta=timedelta(seconds=min_time_delta),
                    correlation_confidence=best_confidence
                )
                self.correlations.append(correlation)
        
        print(f"Found {len(self.correlations)} correlations")

    def generate_summary_report(self) -> str:
        """Generate a summary report of findings"""
        report = []
        report.append("=" * 80)
        report.append("NMX-C FABRIC ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Directory information
        report.append("ANALYSIS DIRECTORY:")
        report.append(f"  nmx-c path: {self.nmx_directory.absolute()}")
        report.append("")
        
        # File information
        report.append("ANALYZED FILES:")
        report.append(f"  Fabric Manager logs: {len(self.fabricmanager_logs)}")
        for fm_log in self.fabricmanager_logs:
            report.append(f"    - {Path(fm_log).name}")
        report.append(f"  nvlSM logs: {len(self.nvlsm_logs)}")
        for nvlsm_log in self.nvlsm_logs:
            report.append(f"    - {Path(nvlsm_log).name}")
        report.append("")
        
        # Summary statistics
        report.append("SUMMARY:")
        report.append(f"  Total trunk port failures: {len(self.trunk_failures)}")
        report.append(f"  Total link down events: {len(self.link_down_events)}")
        report.append(f"  Correlated events: {len(self.correlations)}")
        report.append(f"  Correlation rate: {len(self.correlations)/len(self.trunk_failures)*100:.1f}%" if self.trunk_failures else "  Correlation rate: N/A")
        report.append("")
        
        # Confidence breakdown
        confidence_counts = {}
        for corr in self.correlations:
            confidence_counts[corr.correlation_confidence] = confidence_counts.get(corr.correlation_confidence, 0) + 1
        
        report.append("CORRELATION CONFIDENCE:")
        for confidence, count in confidence_counts.items():
            report.append(f"  {confidence}: {count}")
        report.append("")
        
        # File breakdown
        fm_file_counts = {}
        nvlsm_file_counts = {}
        for tf in self.trunk_failures:
            if tf.source_file:
                fm_file_counts[tf.source_file] = fm_file_counts.get(tf.source_file, 0) + 1
        for ld in self.link_down_events:
            if ld.source_file:
                nvlsm_file_counts[ld.source_file] = nvlsm_file_counts.get(ld.source_file, 0) + 1
        
        report.append("EVENTS BY FILE:")
        report.append("  Fabric Manager:")
        for file, count in fm_file_counts.items():
            report.append(f"    {file}: {count} trunk failures")
        report.append("  nvlSM:")
        for file, count in nvlsm_file_counts.items():
            report.append(f"    {file}: {count} link down events")
        report.append("")
        
        # Detailed correlations
        report.append("CORRELATED EVENTS:")
        report.append("-" * 80)
        
        for i, corr in enumerate(self.correlations, 1):
            report.append(f"\n{i}. CORRELATION (Confidence: {corr.correlation_confidence})")
            report.append(f"   Time Delta: {corr.time_delta.total_seconds():.1f} seconds")
            report.append("")
            
            # Trunk failure details
            tf = corr.trunk_failure
            report.append(f"   TRUNK FAILURE:")
            report.append(f"     Timestamp: {tf.timestamp}")
            report.append(f"     Switch GUID: {tf.switch_guid}")
            report.append(f"     Chassis SN: {tf.chassis_sn}")
            report.append(f"     Slot: {tf.slot}, Port: {tf.port_number}, Cage: {tf.cage}")
            if tf.partition_id:
                report.append(f"     Partition ID: {tf.partition_id}")
            if tf.source_file:
                report.append(f"     Source: {tf.source_file}")
            report.append("")
            
            # Link down details
            ld = corr.link_down
            report.append(f"   LINK DOWN EVENT:")
            report.append(f"     Timestamp: {ld.timestamp}")
            report.append(f"     Switch: {ld.switch_name}")
            report.append(f"     Switch GUID: {ld.switch_guid}")
            report.append(f"     Port: {ld.port_number}")
            report.append(f"     State Change: {ld.state_from} → {ld.state_to}")
            if ld.source_file:
                report.append(f"     Source: {ld.source_file}")
            report.append("")
        
        # Uncorrelated failures
        uncorrelated = [tf for tf in self.trunk_failures 
                       if not any(corr.trunk_failure == tf for corr in self.correlations)]
        
        if uncorrelated:
            report.append("\nUNCORRELATED TRUNK FAILURES:")
            report.append("-" * 80)
            for i, tf in enumerate(uncorrelated, 1):
                report.append(f"\n{i}. {tf.timestamp} - Switch {tf.switch_guid} Port {tf.port_number}")
                report.append(f"   Chassis: {tf.chassis_sn}, Slot: {tf.slot}, Cage: {tf.cage}")
                if tf.source_file:
                    report.append(f"   Source: {tf.source_file}")
        
        return "\n".join(report)

    def export_json(self, filename: str):
        """Export all data to JSON format"""
        data = {
            "metadata": {
                "nmx_directory": str(self.nmx_directory.absolute()),
                "fabricmanager_logs": [Path(f).name for f in self.fabricmanager_logs],
                "nvlsm_logs": [Path(f).name for f in self.nvlsm_logs],
                "analysis_timestamp": datetime.now().isoformat(),
                "summary": {
                    "trunk_failures": len(self.trunk_failures),
                    "link_down_events": len(self.link_down_events),
                    "correlations": len(self.correlations)
                }
            },
            "trunk_failures": [asdict(tf) for tf in self.trunk_failures],
            "link_down_events": [asdict(ld) for ld in self.link_down_events],
            "correlations": [
                {
                    "trunk_failure": asdict(corr.trunk_failure),
                    "link_down": asdict(corr.link_down),
                    "time_delta_seconds": corr.time_delta.total_seconds(),
                    "correlation_confidence": corr.correlation_confidence
                }
                for corr in self.correlations
            ]
        }
        
        # Custom JSON encoder for datetime objects
        def datetime_handler(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=datetime_handler)
        
        print(f"Data exported to {filename}")

    def run_analysis(self):
        """Run the complete analysis"""
        print("Starting NMX-C Fabric Analysis...")
        self.parse_fabricmanager_logs()
        self.parse_nvlsm_logs()
        self.correlate_events()
        return self.generate_summary_report()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NMX-C Fabric Analysis Tool")
    parser.add_argument("--nmx-dir", "-d", default=".",
                       help="Path to nmx-c directory (default: current directory)")
    parser.add_argument("--max-rotated", "-m", type=int, default=10,
                       help="Maximum number of rotated log files to discover (default: 10)")
    parser.add_argument("--output", "-o", default="nmx_analysis_report.txt",
                       help="Output file for the report")
    parser.add_argument("--json", "-j", 
                       help="Export data to JSON file")
    parser.add_argument("--time-window", "-t", type=int, default=10,
                       help="Time window in seconds for correlation (default: 10)")
    
    # Legacy options for backwards compatibility
    parser.add_argument("--fabricmanager", "-f", nargs='+',
                       help="[LEGACY] Path(s) to fabricmanager log files")
    parser.add_argument("--nvlsm", "-n", nargs='+',
                       help="[LEGACY] Path(s) to nvlsm log files")
    parser.add_argument("--auto", "-a", action="store_true",
                       help="[DEPRECATED] Auto-discovery is now the default behavior")
    
    args = parser.parse_args()
    
    # Handle legacy mode
    if args.fabricmanager or args.nvlsm:
        print("WARNING: Using legacy manual file specification mode")
        print("Consider using the new nmx-c directory mode with --nmx-dir instead")
        
        if not args.fabricmanager or not args.nvlsm:
            print("Error: In legacy mode, must specify both --fabricmanager and --nvlsm files")
            return 1
        
        # Validate input files
        for fm_file in args.fabricmanager:
            if not Path(fm_file).exists():
                print(f"Error: Fabric manager log file not found: {fm_file}")
                return 1
        
        for nvlsm_file in args.nvlsm:
            if not Path(nvlsm_file).exists():
                print(f"Error: nvlSM log file not found: {nvlsm_file}")
                return 1
        
        # Create legacy analyzer
        analyzer = NMXAnalyzer(".")
        analyzer.fabricmanager_logs = args.fabricmanager
        analyzer.nvlsm_logs = args.nvlsm
    else:
        # Standard nmx-c directory mode
        if not Path(args.nmx_dir).exists():
            print(f"Error: nmx-c directory not found: {args.nmx_dir}")
            return 1
        
        analyzer = NMXAnalyzer(args.nmx_dir, max_rotated_files=args.max_rotated)
    
    # Check if we found any files to analyze
    if not analyzer.fabricmanager_logs and not analyzer.nvlsm_logs:
        print("Error: No log files found to analyze")
        print("Make sure you're in a valid nmx-c directory or use legacy mode with -f/-n")
        return 1
    
    # Run analysis
    analyzer.time_window = args.time_window
    
    report = analyzer.run_analysis()
    
    # Write report
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"\nReport written to: {args.output}")
    
    # Export JSON if requested
    if args.json:
        analyzer.export_json(args.json)
    
    # Print summary to console
    print("\n" + "=" * 40)
    print("ANALYSIS COMPLETE")
    print("=" * 40)
    print(f"Trunk failures found: {len(analyzer.trunk_failures)}")
    print(f"Link down events found: {len(analyzer.link_down_events)}")
    print(f"Successful correlations: {len(analyzer.correlations)}")
    
    return 0


if __name__ == "__main__":
    exit(main()) 