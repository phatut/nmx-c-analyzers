#!/usr/bin/env python3
"""
NMX-C Fabric Table Analysis Tool
Creates table format reports for trunk port failures, port down events, and GPU NVL errors.
Enhanced with access port vs trunk port classification.
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
class GPUNVLError:
    """GPU NVL error event with XID correlation"""
    timestamp: datetime
    tid: int
    severity: str  # "Non Fatal" or "Fatal"
    moduleId: int
    nodeId: int
    partition_id: int
    gpu_guid: str
    port_num: int
    port_status: int
    error_code: str
    error_subcode: str
    port_down_reason_code: str
    is_error_first: int
    error_status: str
    error_debug_data: str
    source_file: Optional[str] = None
    # XID equivalent fields
    equivalent_xid: Optional[int] = None
    resolution: Optional[str] = None
    comments: Optional[str] = None
    
    def __post_init__(self):
        """Map GPU NVL error to XID equivalent"""
        self.map_to_xid_equivalent()
    
    def map_to_xid_equivalent(self):
        """Map GPU error codes to known XID equivalents"""
        # GPU NVL error code to XID mapping
        error_mappings = {
            "0x02_0x07": {
                "xid": 149,
                "resolution": "RESET_GPU",
                "comments": "GPU NVL Non-Fatal Error - Link training failure"
            },
            "0x03_0x01": {
                "xid": 79,
                "resolution": "RESET_GPU", 
                "comments": "GPU NVL Fatal Error - Critical link failure"
            },
            "0x01_0x05": {
                "xid": 149,
                "resolution": "CHECK_CABLE",
                "comments": "GPU NVL Error - Physical layer issue"
            }
        }
        
        error_key = f"{self.error_code}_{self.error_subcode}"
        if error_key in error_mappings:
            mapping = error_mappings[error_key]
            self.equivalent_xid = mapping["xid"]
            self.resolution = mapping["resolution"]
            self.comments = mapping["comments"]
        else:
            # Default mapping for unknown error codes
            self.equivalent_xid = 149  # Generic NVLink error
            self.resolution = "INVESTIGATE"
            self.comments = f"GPU NVL Error: {self.error_code}/{self.error_subcode}"


@dataclass
class PortDownEvent:
    """Fabric manager port down event"""
    timestamp: datetime
    switch_guid: str
    port_guid: str
    port_num: int
    tid: Optional[int] = None
    source_file: Optional[str] = None
    port_type: Optional[str] = None  # "access", "trunk", or "unknown"
    link_partner_guid: Optional[str] = None
    link_partner_port: Optional[int] = None


@dataclass
class TrunkFailureEvent:
    """Combined trunk failure and link down event with associated GPU NVL errors"""
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
    associated_gpu_errors: List[GPUNVLError] = None
    # New fields for port down events
    port_type: Optional[str] = None  # "access", "trunk"
    event_type: Optional[str] = None  # "trunk_failure", "port_down"
    
    def __post_init__(self):
        if self.associated_gpu_errors is None:
            self.associated_gpu_errors = []


@dataclass 
class LinkPartner:
    """Represents a link connection between two switches or switch-to-GPU"""
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
        """Parse SMDB file and extract all link topology (switch-switch and switch-GPU)"""
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
                    
            print(f"Found {links_count} total links in SMDB")
            
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
    
    def classify_port_type(self, switch_guid: str, port: int) -> str:
        """Classify port as 'access' (GPU), 'trunk' (switch), or 'unknown'"""
        partner = self.find_link_partner(switch_guid, port)
        if not partner:
            return "unknown"
        
        partner_guid, _ = partner
        
        # Switch GUIDs start with 0xb0cf0e0300
        # GPU GUIDs have different patterns
        if partner_guid.lower().startswith('0xb0cf0e0300'):
            return "trunk"  # Connected to another switch
        else:
            return "access"  # Connected to GPU


class NMXTableAnalyzer:
    """Enhanced analyzer for table format trunk failure reports with GPU correlation"""
    
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
        
        # Regex patterns for original trunk failures
        self.trunk_failure_pattern = re.compile(
            r'\[([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\] \[WARNING\] \[tid (\d+)\] '
            r'Trunk port failure detected for switch GUID (0x[a-fA-F0-9]+) and switch chassis sn (\d+), '
            r'slot (\d+) port number (\d+) port GUID (0x[a-fA-F0-9]+) cage (\d+)\.'
        )
        
        self.trunk_link_failure_pattern = re.compile(
            r'\[([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\] \[WARNING\] \[tid (\d+)\] '
            r'Detected a trunk link failure event for partition Id (\d+)\.'
        )
        
        # GPU NVL error patterns
        self.gpu_nvl_error_pattern = re.compile(
            r'\[([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\] \[ERROR\] \[tid (\d+)\] '
            r'Fabric Manager detected GPU NVL (Non Fatal|Fatal) error on :'
        )
        
        # Port down event patterns
        self.port_down_event_pattern = re.compile(
            r'\[([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\] \[INFO\] \[tid (\d+)\] '
            r'fabric manager received port down event on switch with GUID (0x[a-fA-F0-9]+), '
            r'port GUID (0x[a-fA-F0-9]+), and port num (\d+)'
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
        """Collect and correlate all failure events from logs"""
        print("Collecting failure events...")
        
        # Collect fabric manager failures (original trunk failures)
        fm_failures = self._parse_fabric_manager_failures()
        
        # Collect port down events (new format)
        port_down_events = self._parse_port_down_events()
        
        # Collect GPU NVL errors
        gpu_errors = self._parse_gpu_nvl_errors()
        
        # Collect nvlSM link down events
        sm_events = self._parse_nvlsm_events()
        
        # Correlate original trunk failures
        if fm_failures:
            self._correlate_events(fm_failures, sm_events, gpu_errors, "trunk_failure")
        
        # Correlate port down events
        if port_down_events:
            self._correlate_port_down_events(port_down_events, sm_events, gpu_errors)
        
        print(f"Collected {len(self.trunk_events)} correlated failure events")
        
        # Debug output
        if port_down_events:
            print(f"Debug: Found {len(port_down_events)} port down events")
            access_ports = sum(1 for event in self.trunk_events if event.port_type == "access")
            trunk_ports = sum(1 for event in self.trunk_events if event.port_type == "trunk")
            print(f"Debug: {access_ports} access ports, {trunk_ports} trunk ports")

    def _parse_gpu_nvl_errors(self) -> List[GPUNVLError]:
        """Parse fabric manager logs for GPU NVL errors"""
        gpu_errors = []
        
        for log_file in self.fabricmanager_logs:
            print(f"  Processing GPU errors: {Path(log_file).name}")
            try:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                    i = 0
                    while i < len(lines):
                        line = lines[i]
                        match = self.gpu_nvl_error_pattern.search(line)
                        if match:
                            timestamp = self.parse_timestamp_fm(match.group(1))
                            tid = int(match.group(2))
                            severity = match.group(3)
                            
                            # Parse multi-line GPU error details
                            gpu_data = {}
                            j = i + 1
                            while j < len(lines) and j < i + 20:  # Look ahead up to 20 lines
                                detail_line = lines[j].strip()
                                if ':' in detail_line and not detail_line.startswith('['):
                                    parts = detail_line.split(':', 1)
                                    if len(parts) == 2:
                                        key = parts[0].strip()
                                        value = parts[1].strip()
                                        gpu_data[key] = value
                                elif detail_line.startswith('[') or not detail_line:
                                    break
                                j += 1
                            
                            # Create GPU error object if we have essential data
                            if all(key in gpu_data for key in ['moduleId', 'nodeId', 'gpuGuid', 'portNum', 'errorCode', 'errorSubcode']):
                                gpu_error = GPUNVLError(
                                    timestamp=timestamp,
                                    tid=tid,
                                    severity=severity,
                                    moduleId=int(gpu_data.get('moduleId', 0)),
                                    nodeId=int(gpu_data.get('nodeId', 0)),
                                    partition_id=int(gpu_data.get('partitionId', 0)),
                                    gpu_guid=gpu_data.get('gpuGuid', ''),
                                    port_num=int(gpu_data.get('portNum', 0)),
                                    port_status=int(gpu_data.get('portStatus', 0)),
                                    error_code=gpu_data.get('errorCode', ''),
                                    error_subcode=gpu_data.get('errorSubcode', ''),
                                    port_down_reason_code=gpu_data.get('portDownReasonCode', ''),
                                    is_error_first=int(gpu_data.get('isErrorFirst', 0)),
                                    error_status=gpu_data.get('errorStatus', ''),
                                    error_debug_data=gpu_data.get('errorDebugData', ''),
                                    source_file=Path(log_file).name
                                )
                                gpu_errors.append(gpu_error)
                            
                            i = j  # Continue from where we left off
                        else:
                            i += 1
                            
            except Exception as e:
                print(f"  Error processing GPU errors in {Path(log_file).name}: {e}")
        
        print(f"Found {len(gpu_errors)} GPU NVL errors")
        return gpu_errors

    def _parse_port_down_events(self) -> List[PortDownEvent]:
        """Parse fabric manager logs for port down events"""
        port_events = []
        
        for log_file in self.fabricmanager_logs:
            print(f"  Processing port down events: {Path(log_file).name}")
            try:
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = self.port_down_event_pattern.search(line)
                        if match:
                            timestamp = self.parse_timestamp_fm(match.group(1))
                            tid = int(match.group(2))
                            switch_guid = match.group(3)
                            port_guid = match.group(4)
                            port_num = int(match.group(5))
                            
                            # Classify port type using SMDB
                            port_type = "unknown"
                            link_partner_guid = None
                            link_partner_port = None
                            
                            if self.smdb_parser:
                                port_type = self.smdb_parser.classify_port_type(switch_guid, port_num)
                                partner = self.smdb_parser.find_link_partner(switch_guid, port_num)
                                if partner:
                                    link_partner_guid, link_partner_port = partner
                            
                            event = PortDownEvent(
                                timestamp=timestamp,
                                switch_guid=switch_guid,
                                port_guid=port_guid,
                                port_num=port_num,
                                tid=tid,
                                source_file=Path(log_file).name,
                                port_type=port_type,
                                link_partner_guid=link_partner_guid,
                                link_partner_port=link_partner_port
                            )
                            port_events.append(event)
                            
            except Exception as e:
                print(f"  Error processing port down events in {Path(log_file).name}: {e}")
        
        print(f"Found {len(port_events)} port down events")
        return port_events

    def _parse_fabric_manager_failures(self) -> List[dict]:
        """Parse fabric manager logs for original trunk failures"""
        failures = []
        current_partition_id = None
        
        for log_file in self.fabricmanager_logs:
            print(f"  Processing FM original: {Path(log_file).name}")
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

    def _correlate_events(self, fm_failures: List[dict], sm_events: List[dict], gpu_errors: List[GPUNVLError], event_type: str, time_window: int = 10):
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
                
                # Find associated GPU NVL errors with TIGHT correlation (≤5 seconds)
                associated_errors = []
                for gpu_error in gpu_errors:
                    error_time_delta = abs((failure['timestamp'] - gpu_error.timestamp).total_seconds())
                    # STRICT correlation: ≤5 seconds AND matching partition/port+GUID
                    if (error_time_delta <= 5 and  # Tight time window (no false correlations)
                        (gpu_error.partition_id == failure.get('partition_id') or
                         (gpu_error.port_num == failure['port'] and 
                          gpu_error.gpu_guid and failure['switch_guid'].replace('0x', '').lower() in gpu_error.gpu_guid.lower()))):
                        associated_errors.append(gpu_error)
                
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
                    link_partner_port=link_partner_port,
                    associated_gpu_errors=associated_errors,
                    port_type=self.smdb_parser.classify_port_type(failure['switch_guid'], failure['port']) if self.smdb_parser else "trunk",  # Original trunk failures
                    event_type=event_type
                )
                self.trunk_events.append(event)

    def _correlate_port_down_events(self, port_events: List[PortDownEvent], sm_events: List[dict], gpu_errors: List[GPUNVLError], time_window: int = 10):
        """Correlate port down events with SM events and GPU errors"""
        for port_event in port_events:
            # Find matching SM event
            best_match = None
            min_time_delta = None
            
            for sm_event in sm_events:
                if (port_event.switch_guid.lower() == sm_event['switch_guid'].lower() and
                    port_event.port_num == sm_event['port']):
                    
                    time_delta = abs((port_event.timestamp - sm_event['timestamp']).total_seconds())
                    if time_delta <= time_window:
                        if min_time_delta is None or time_delta < min_time_delta:
                            min_time_delta = time_delta
                            best_match = sm_event
            
            # Create event even without SM match (some port down events may not have corresponding SM events)
            switch_name = best_match['switch_name'] if best_match else f"Switch-{port_event.switch_guid[-8:]}"
            state_from = best_match['state_from'] if best_match else "UNKNOWN"
            state_to = best_match['state_to'] if best_match else "DOWN"
            
            # Find associated GPU NVL errors with TIGHT correlation (≤5 seconds)
            associated_errors = []
            for gpu_error in gpu_errors:
                error_time_delta = abs((port_event.timestamp - gpu_error.timestamp).total_seconds())
                # STRICT correlation: ≤5 seconds AND matching partition/port+GUID
                if (error_time_delta <= 5 and  # Tight time window (no false correlations)
                    (gpu_error.partition_id == None or  # Port down events may not have partition ID
                     (gpu_error.port_num == port_event.port_num and 
                      gpu_error.gpu_guid and port_event.switch_guid.replace('0x', '').lower() in gpu_error.gpu_guid.lower()))):
                    associated_errors.append(gpu_error)
            
            event = TrunkFailureEvent(
                timestamp=port_event.timestamp,
                switch_guid=port_event.switch_guid,
                switch_name=switch_name,
                chassis_sn="Unknown",  # Port down events don't have chassis info
                slot=0,  # Port down events don't have slot info
                port=port_event.port_num,
                cage=0,  # Port down events don't have cage info
                state_from=state_from,
                state_to=state_to,
                partition_id=None,  # Port down events don't have partition ID
                tid=port_event.tid,
                fm_source=port_event.source_file,
                sm_source=best_match['source'] if best_match else None,
                link_partner_guid=port_event.link_partner_guid,
                link_partner_port=port_event.link_partner_port,
                associated_gpu_errors=associated_errors,
                port_type=port_event.port_type,  # "access", "trunk", or "unknown"
                event_type="port_down"
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
        """Generate enhanced table format report with GPU errors"""
        print("Generating table format report...")
        
        groups = self._group_link_partners()
        
        with open(output_file, 'w') as f:
            f.write("FABRIC LINK FAILURES AND GPU ERRORS REPORT\n")
            f.write("=" * 122 + "\n\n")
            
            # Table header
            header = (
                f"{'#':<3} {'Timestamp':<19} {'Switch/GPU GUID':<18} {'Port':<4} {'Type':<6} "
                f"{'Event/Error':<12} {'Details':<35} {'XID/Partner':<20} {'Detected In':<15}\n"
            )
            f.write(header)
            f.write("-" * 122 + "\n")
            
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
                    sources = f"{event.fm_source[0:3]}" + (f"/{event.sm_source[0:3]}" if event.sm_source else "")  # Abbreviated sources
                    
                    incident_id = f"{incident_num}" if i == 0 else ""
                    
                    # Determine port type display
                    port_type_display = "Link"
                    if event.port_type == "access":
                        port_type_display = "Access"
                    elif event.port_type == "trunk":
                        port_type_display = "Trunk"
                    
                    line = (
                        f"{incident_id:<3} {event.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<19} "
                        f"{switch_guid_short:<18} {event.port:<4} {port_type_display:<6} "
                        f"{state_change:<12} {switch_name_short:<35} {partner_info:<20} {sources:<15}\n"
                    )
                    f.write(line)
                    
                    # Write associated GPU errors as indented sub-entries
                    for gpu_error in event.associated_gpu_errors:
                        gpu_guid_short = gpu_error.gpu_guid[-8:] if gpu_error.gpu_guid else "Unknown"
                        severity_short = gpu_error.severity.replace("Non ", "N-")
                        error_details = f"{gpu_error.error_code}/{gpu_error.error_subcode} {severity_short}"
                        xid_info = f"XID {gpu_error.equivalent_xid}"
                        action = gpu_error.resolution
                        
                        gpu_line = (
                            f"{'├─':<3} {gpu_error.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<19} "
                            f"{gpu_guid_short:<18} {gpu_error.port_num:<4} {'GPU':<6} "
                            f"{error_details:<12} {gpu_error.comments[:33]:<35} {xid_info:<20} {action:<15}\n"
                        )
                        f.write(gpu_line)
                
                # Add separator between incidents
                if len(group) > 1 or incident_num < len(groups):
                    f.write("\n")
                
                incident_num += 1
            
            # Summary
            f.write("\n" + "=" * 122 + "\n")
            access_count = sum(1 for e in self.trunk_events if e.port_type == "access")
            trunk_count = sum(1 for e in self.trunk_events if e.port_type == "trunk")
            gpu_error_count = sum(len(e.associated_gpu_errors) for e in self.trunk_events)
            
            f.write(f"SUMMARY: {len(self.trunk_events)} events in {len(groups)} incidents\n")
            f.write(f"Port Types: {access_count} access, {trunk_count} trunk\n")
            f.write(f"GPU Errors Correlated: {gpu_error_count}\n")
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
                'Link_Partner_GUID', 'Link_Partner_Port', 'FM_Source', 'SM_Source',
                'Port_Type', 'Event_Type', 'GPU_Errors_Count'
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
                    event.sm_source or '',
                    event.port_type or '',
                    event.event_type or '',
                    len(event.associated_gpu_errors)
                ])
        
        print(f"CSV report written to: {output_file}")
        
        # Export GPU errors separately
        self._export_gpu_errors_csv(output_file.replace('.csv', '_gpu_errors.csv'))

    def _export_gpu_errors_csv(self, output_file: str):
        """Export detailed GPU error data with trunk failure context"""
        all_gpu_errors = []
        for event in self.trunk_events:
            for gpu_error in event.associated_gpu_errors:
                error_data = asdict(gpu_error)
                error_data['trunk_event_timestamp'] = event.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                error_data['trunk_switch_guid'] = event.switch_guid
                error_data['trunk_port'] = event.port
                error_data['trunk_port_type'] = event.port_type
                all_gpu_errors.append(error_data)
        
        if all_gpu_errors:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=all_gpu_errors[0].keys())
                writer.writeheader()
                writer.writerows(all_gpu_errors)
            print(f"GPU errors CSV written to: {output_file}")

    def run_analysis(self):
        """Run the complete table analysis"""
        print("Starting NMX-C Enhanced Analysis...")
        self.collect_events()
        return len(self.trunk_events)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NMX-C Enhanced Fabric Analysis Tool")
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
        print("No failure events found to analyze")
        return 1
    
    # Generate reports
    analyzer.generate_table_report(args.output)
    
    if args.csv:
        analyzer.generate_csv_report(args.csv)
    
    print("\n" + "=" * 50)
    print("ENHANCED ANALYSIS COMPLETE")
    print("=" * 50)
    print(f"Events analyzed: {event_count}")
    access_count = sum(1 for e in analyzer.trunk_events if e.port_type == "access")
    trunk_count = sum(1 for e in analyzer.trunk_events if e.port_type == "trunk")
    gpu_count = sum(len(e.associated_gpu_errors) for e in analyzer.trunk_events)
    print(f"Port breakdown: {access_count} access, {trunk_count} trunk")
    print(f"GPU errors found: {gpu_count}")
    
    return 0


if __name__ == "__main__":
    exit(main()) 