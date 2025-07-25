#!/usr/bin/env python3
"""
NMX-C Fabric Table Analysis Tool
Creates table format reports for trunk port failures with link partner correlation.
"""

import re
import gzip
import json
import csv
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class TrunkFailureEvent:
    """Combined trunk failure and link down event"""
    timestamp: datetime
    switch_guid: str
    switch_name: str
    chassis_sn: str
    slot: int
    port: int
    cage: int
    state_from: str
    state_to: str
    partition_id: Optional[int] = None
    tid: Optional[int] = None
    fm_source: Optional[str] = None
    sm_source: Optional[str] = None
    link_partner_guid: Optional[str] = None
    link_partner_port: Optional[int] = None


@dataclass 
class LinkPartner:
    """Represents a link connection between two switches"""
    guid1: str
    port1: int
    guid2: str
    port2: int


class SMDBParser:
    """Parser for SMDB dump files to extract link topology"""
    
    def __init__(self, smdb_file: str):
        self.smdb_file = smdb_file
        self.links: List[LinkPartner] = []
        self.switch_names: Dict[str, str] = {}
        
    def parse(self):
        """Parse SMDB file and extract link topology"""
        print(f"Parsing SMDB file: {Path(self.smdb_file).name}")
        
        try:
            with gzip.open(self.smdb_file, 'rt', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Find LINKS section
            lines = content.split('\n')
            in_links_section = False
            links_count = 0
            
            for line in lines:
                line = line.strip()
                
                if line == "NodeGUID1, PortNum1, NodeGUID2, PortNum2":
                    in_links_section = True
                    continue
                elif line.startswith("0x") and in_links_section:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 4:
                        # Only capture switch-to-switch links (both GUIDs starting with 0xb0cf0e0300)
                        if (parts[0].startswith('0xb0cf0e0300') and 
                            parts[2].startswith('0xb0cf0e0300')):
                            try:
                                link = LinkPartner(
                                    guid1=parts[0],
                                    port1=int(parts[1]),
                                    guid2=parts[2], 
                                    port2=int(parts[3])
                                )
                                self.links.append(link)
                                links_count += 1
                            except ValueError:
                                continue
                elif line.startswith("END_") or (in_links_section and not line.startswith("0x") and line):
                    in_links_section = False
                    
            print(f"Found {links_count} trunk links in SMDB")
            
        except Exception as e:
            print(f"Error parsing SMDB file: {e}")
    
    def find_link_partner(self, guid: str, port: int) -> Optional[Tuple[str, int]]:
        """Find the link partner for a given GUID and port"""
        for link in self.links:
            if link.guid1.lower() == guid.lower() and link.port1 == port:
                return (link.guid2, link.port2)
            elif link.guid2.lower() == guid.lower() and link.port2 == port:
                return (link.guid1, link.port1)
        return None


class NMXTableAnalyzer:
    """Enhanced analyzer for table format trunk failure reports"""
    
    def __init__(self, nmx_directory: str = ".", max_rotated_files: int = 10):
        self.nmx_directory = Path(nmx_directory)
        self.max_rotated_files = max_rotated_files
        self.fabricmanager_logs: List[str] = []
        self.nvlsm_logs: List[str] = []
        self.smdb_parser: Optional[SMDBParser] = None
        self.trunk_events: List[TrunkFailureEvent] = []
        
        # Auto-discover files
        self._discover_nmx_files()
        
        # Parse SMDB if available
        self._init_smdb_parser()
        
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

    def _discover_nmx_files(self):
        """Auto-discover log files and SMDB dump"""
        print(f"Analyzing nmx-c directory: {self.nmx_directory.absolute()}")
        
        # Fabric manager logs
        fm_base = self.nmx_directory / "fabricmanager.log.gz"
        if fm_base.exists():
            self.fabricmanager_logs.append(str(fm_base))
        
        for i in range(1, self.max_rotated_files + 1):
            fm_rotated = self.nmx_directory / f"fabricmanager.log.{i}.gz"
            if fm_rotated.exists():
                self.fabricmanager_logs.append(str(fm_rotated))
        
        # nvlSM logs
        nvlsm_base = self.nmx_directory / "nvlsm.log.gz"
        if nvlsm_base.exists():
            self.nvlsm_logs.append(str(nvlsm_base))
            
        for i in range(1, self.max_rotated_files + 1):
            nvlsm_rotated = self.nmx_directory / f"nvlsm.log.{i}.gz"
            if nvlsm_rotated.exists():
                self.nvlsm_logs.append(str(nvlsm_rotated))
        
        print(f"Found {len(self.fabricmanager_logs)} fabric manager logs")
        print(f"Found {len(self.nvlsm_logs)} nvlsm logs")

    def _init_smdb_parser(self):
        """Initialize SMDB parser if dump file exists"""
        smdb_file = self.nmx_directory / "dumps" / "nvlsm-smdb.dump.gz"
        if smdb_file.exists():
            self.smdb_parser = SMDBParser(str(smdb_file))
            self.smdb_parser.parse()
        else:
            print("WARNING: SMDB dump file not found - link partner correlation disabled")

    def parse_timestamp_fm(self, timestamp_str: str) -> datetime:
        """Parse fabric manager timestamp"""
        return datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
    
    def parse_timestamp_nvlsm(self, timestamp_str: str) -> datetime:
        """Parse nvlSM timestamp"""
        return datetime.strptime(f"2025 {timestamp_str}", "%Y %b %d %H:%M:%S")

    def collect_events(self):
        """Collect and correlate trunk failure events from both logs"""
        print("Collecting trunk failure events...")
        
        # Collect fabric manager failures
        fm_failures = self._parse_fabric_manager_failures()
        
        # Collect nvlSM link down events
        sm_events = self._parse_nvlsm_events()
        
        # Correlate events
        self._correlate_events(fm_failures, sm_events)
        
        print(f"Collected {len(self.trunk_events)} correlated trunk failure events")

    def _parse_fabric_manager_failures(self) -> List[dict]:
        """Parse fabric manager logs for trunk failures"""
        failures = []
        current_partition_id = None
        
        for log_file in self.fabricmanager_logs:
            print(f"  Processing FM: {Path(log_file).name}")
            try:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        # Check for partition failure events first
                        match = self.trunk_link_failure_pattern.search(line)
                        if match:
                            current_partition_id = int(match.group(3))
                            continue
                            
                        # Check for trunk port failures
                        match = self.trunk_failure_pattern.search(line)
                        if match:
                            failure = {
                                'timestamp': self.parse_timestamp_fm(match.group(1)),
                                'tid': int(match.group(2)),
                                'switch_guid': match.group(3),
                                'chassis_sn': match.group(4),
                                'slot': int(match.group(5)),
                                'port': int(match.group(6)),
                                'port_guid': match.group(7),
                                'cage': int(match.group(8)),
                                'partition_id': current_partition_id,
                                'source': Path(log_file).name
                            }
                            failures.append(failure)
            except Exception as e:
                print(f"  Error processing {Path(log_file).name}: {e}")
        
        return failures

    def _parse_nvlsm_events(self) -> List[dict]:
        """Parse nvlSM logs for link down events"""
        events = []
        
        for log_file in self.nvlsm_logs:
            print(f"  Processing SM: {Path(log_file).name}")
            try:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = self.link_down_pattern.search(line)
                        if match and match.group(9) == "DOWN":
                            event = {
                                'timestamp': self.parse_timestamp_nvlsm(match.group(1)),
                                'thread_id': match.group(2),
                                'switch_guid': match.group(3),
                                'switch_name': f"{match.group(4)};{match.group(5)}:{match.group(6)}",
                                'port': int(match.group(7)),
                                'state_from': match.group(8),
                                'state_to': match.group(9),
                                'source': Path(log_file).name
                            }
                            events.append(event)
            except Exception as e:
                print(f"  Error processing {Path(log_file).name}: {e}")
        
        return events

    def _correlate_events(self, fm_failures: List[dict], sm_events: List[dict], time_window: int = 10):
        """Correlate FM failures with SM events"""
        for failure in fm_failures:
            # Find matching SM event
            best_match = None
            min_time_delta = None
            
            for sm_event in sm_events:
                if (failure['switch_guid'].lower() == sm_event['switch_guid'].lower() and
                    failure['port'] == sm_event['port']):
                    
                    time_delta = abs((failure['timestamp'] - sm_event['timestamp']).total_seconds())
                    if time_delta <= time_window:
                        if min_time_delta is None or time_delta < min_time_delta:
                            min_time_delta = time_delta
                            best_match = sm_event
            
            # Create combined event
            if best_match:
                # Find link partner if SMDB is available
                link_partner_guid = None
                link_partner_port = None
                if self.smdb_parser:
                    partner = self.smdb_parser.find_link_partner(failure['switch_guid'], failure['port'])
                    if partner:
                        link_partner_guid, link_partner_port = partner
                
                event = TrunkFailureEvent(
                    timestamp=failure['timestamp'],
                    switch_guid=failure['switch_guid'],
                    switch_name=best_match['switch_name'],
                    chassis_sn=failure['chassis_sn'],
                    slot=failure['slot'],
                    port=failure['port'],
                    cage=failure['cage'],
                    state_from=best_match['state_from'],
                    state_to=best_match['state_to'],
                    partition_id=failure.get('partition_id'),
                    tid=failure.get('tid'),
                    fm_source=failure['source'],
                    sm_source=best_match['source'],
                    link_partner_guid=link_partner_guid,
                    link_partner_port=link_partner_port
                )
                self.trunk_events.append(event)

    def _group_link_partners(self) -> List[List[TrunkFailureEvent]]:
        """Group events by link partners"""
        groups = []
        processed = set()
        
        for event in self.trunk_events:
            if id(event) in processed:
                continue
                
            group = [event]
            processed.add(id(event))
            
            # Find partner event if it exists
            if event.link_partner_guid:
                for other_event in self.trunk_events:
                    if (id(other_event) not in processed and
                        other_event.switch_guid.lower() == event.link_partner_guid.lower() and
                        other_event.port == event.link_partner_port and
                        abs((event.timestamp - other_event.timestamp).total_seconds()) <= 5):
                        group.append(other_event)
                        processed.add(id(other_event))
                        break
            
            groups.append(group)
        
        return groups

    def generate_table_report(self, output_file: str = "trunk_failures_table.txt"):
        """Generate table format report"""
        print("Generating table format report...")
        
        groups = self._group_link_partners()
        
        with open(output_file, 'w') as f:
            f.write("TRUNK LINK FAILURES REPORT\n")
            f.write("=" * 120 + "\n\n")
            
            # Table header
            header = (
                f"{'#':<3} {'Timestamp':<19} {'Switch GUID':<18} {'Port':<4} {'Cage':<4} "
                f"{'State Change':<12} {'Switch Name':<35} {'Partner':<20} {'Sources':<15}\n"
            )
            f.write(header)
            f.write("-" * 120 + "\n")
            
            incident_num = 1
            for group in groups:
                # Sort group by timestamp
                group.sort(key=lambda x: x.timestamp)
                
                for i, event in enumerate(group):
                    partner_info = ""
                    if event.link_partner_guid:
                        partner_guid_short = event.link_partner_guid[-8:]  # Last 8 chars
                        partner_info = f"{partner_guid_short}:{event.link_partner_port}"
                    
                    state_change = f"{event.state_from}→{event.state_to}"
                    switch_guid_short = event.switch_guid[-8:]  # Last 8 chars for clarity
                    switch_name_short = event.switch_name.split(';')[-1][:33]  # Abbreviated switch name
                    sources = f"{event.fm_source[0:3]}/{event.sm_source[0:3]}"  # Abbreviated sources
                    
                    incident_id = f"{incident_num}" if i == 0 else ""
                    
                    line = (
                        f"{incident_id:<3} {event.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<19} "
                        f"{switch_guid_short:<18} {event.port:<4} {event.cage:<4} "
                        f"{state_change:<12} {switch_name_short:<35} {partner_info:<20} {sources:<15}\n"
                    )
                    f.write(line)
                
                # Add separator between incidents
                if len(group) > 1 or incident_num < len(groups):
                    f.write("\n")
                
                incident_num += 1
            
            # Summary
            f.write("\n" + "=" * 120 + "\n")
            f.write(f"SUMMARY: {len(self.trunk_events)} events in {len(groups)} incidents\n")
            if self.smdb_parser:
                partnered_events = sum(1 for e in self.trunk_events if e.link_partner_guid)
                f.write(f"Link partners identified: {partnered_events}/{len(self.trunk_events)} events\n")
        
        print(f"Table report written to: {output_file}")

    def generate_csv_report(self, output_file: str = "trunk_failures.csv"):
        """Generate CSV format for further analysis"""
        print("Generating CSV report...")
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Timestamp', 'Switch_GUID', 'Switch_Name', 'Port', 'Cage', 'Slot',
                'State_From', 'State_To', 'Chassis_SN', 'Partition_ID', 'TID',
                'Link_Partner_GUID', 'Link_Partner_Port', 'FM_Source', 'SM_Source'
            ])
            
            # Data rows
            for event in sorted(self.trunk_events, key=lambda x: x.timestamp):
                writer.writerow([
                    event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    event.switch_guid,
                    event.switch_name,
                    event.port,
                    event.cage,
                    event.slot,
                    event.state_from,
                    event.state_to,
                    event.chassis_sn,
                    event.partition_id,
                    event.tid,
                    event.link_partner_guid or '',
                    event.link_partner_port or '',
                    event.fm_source,
                    event.sm_source
                ])
        
        print(f"CSV report written to: {output_file}")

    def run_analysis(self):
        """Run the complete table analysis"""
        print("Starting NMX-C Table Analysis...")
        self.collect_events()
        return len(self.trunk_events)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NMX-C Fabric Table Analysis Tool")
    parser.add_argument("--nmx-dir", "-d", default=".",
                       help="Path to nmx-c directory (default: current directory)")
    parser.add_argument("--max-rotated", "-m", type=int, default=10,
                       help="Maximum number of rotated log files to discover (default: 10)")
    parser.add_argument("--output", "-o", default="trunk_failures_table.txt",
                       help="Output file for the table report")
    parser.add_argument("--csv", "-c", 
                       help="Generate CSV format report")
    parser.add_argument("--time-window", "-t", type=int, default=10,
                       help="Time window in seconds for correlation (default: 10)")
    
    args = parser.parse_args()
    
    # Validate directory
    if not Path(args.nmx_dir).exists():
        print(f"Error: nmx-c directory not found: {args.nmx_dir}")
        return 1
    
    # Run analysis
    analyzer = NMXTableAnalyzer(args.nmx_dir, max_rotated_files=args.max_rotated)
    
    event_count = analyzer.run_analysis()
    if event_count == 0:
        print("No trunk failure events found to analyze")
        return 1
    
    # Generate reports
    analyzer.generate_table_report(args.output)
    
    if args.csv:
        analyzer.generate_csv_report(args.csv)
    
    print("\n" + "=" * 40)
    print("TABLE ANALYSIS COMPLETE")
    print("=" * 40)
    print(f"Events analyzed: {event_count}")
    
    return 0


if __name__ == "__main__":
    exit(main()) 