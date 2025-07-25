#!/usr/bin/env python3
"""
High-Performance NMX-C Table Analyzer with Multi-threading
Optimized for large directories with multiple rotated log files
"""

import gzip
import re
import asyncio
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Iterator
import json
import threading
from collections import defaultdict
import time
import multiprocessing as mp

@dataclass
class TrunkFailureEvent:
    timestamp: datetime
    switch_guid: str
    switch_name: str
    port: int
    cage: int
    slot: int
    state_from: str
    state_to: str
    chassis_sn: str
    partition_id: Optional[int]
    tid: int
    link_partner_guid: Optional[str] = None
    link_partner_port: Optional[int] = None
    fm_source: Optional[str] = None
    sm_source: Optional[str] = None
    port_type: str = "unknown"
    event_type: str = "trunk_failure"
    associated_gpu_errors: List = field(default_factory=list)

@dataclass
class PortDownEvent:
    timestamp: datetime
    switch_guid: str
    port_guid: str
    port_num: int
    switch_name: str = "Unknown"
    port_type: str = "unknown"
    link_partner_guid: Optional[str] = None
    link_partner_port: Optional[int] = None
    fm_source: Optional[str] = None
    sm_source: Optional[str] = None
    event_type: str = "port_down"
    associated_gpu_errors: List = field(default_factory=list)

@dataclass
class GPUNVLError:
    timestamp: datetime
    gpu_guid: str
    port_num: Optional[int]
    error_timestamp: datetime
    severity: str
    switch_guid: str
    switch_instance: int
    gpu_instance: int
    partition_id: int
    nvl_link: int
    link_id: int
    error_code: str
    error_subcode: str
    error_data: str
    equivalent_xid: Optional[int] = None
    resolution: str = "Unknown"
    description: str = "GPU NVL Error"
    source_file: str = ""
    
    def __post_init__(self):
        """Auto-map to XID equivalent after initialization"""
        self.map_to_xid_equivalent()
    
    def map_to_xid_equivalent(self):
        """Map GPU NVL error codes to equivalent XID information"""
        # Map common error codes to XID equivalents
        error_key = f"{self.error_code}_{self.error_subcode}"
        
        # Comprehensive XID mapping based on NVIDIA documentation
        xid_mapping = {
            "0x02_0x07": {"xid": 149, "resolution": "RESET_GPU", "description": "NVLink port down event"},
            "0x02_0x08": {"xid": 145, "resolution": "RESET_GPU", "description": "NVLink recovery event"},
            "0x01_0x01": {"xid": 144, "resolution": "INVESTIGATE", "description": "NVLink training failure"},
            "0x03_0x01": {"xid": 150, "resolution": "RESET_GPU", "description": "NVLink timeout error"},
            "0x02_0x01": {"xid": 149, "resolution": "RESET_GPU", "description": "NVLink lane failure"},
            "0x01_0x02": {"xid": 144, "resolution": "CHECK_CABLES", "description": "NVLink link training error"},
            "0x04_0x01": {"xid": 151, "resolution": "RESET_GPU", "description": "NVLink protocol error"},
        }
        
        if error_key in xid_mapping:
            mapping = xid_mapping[error_key]
            self.equivalent_xid = mapping["xid"]
            self.resolution = mapping["resolution"]
            self.description = mapping["description"]
        else:
            # Default for unmapped errors
            self.equivalent_xid = 149  # Generic NVLink error
            self.resolution = "INVESTIGATE"
            self.description = "Unmapped GPU NVL Error"

class FastSMDBParser:
    """Optimized SMDB parser with caching and parallel processing"""
    
    def __init__(self):
        self.links: Dict[Tuple[str, int], Tuple[str, int]] = {}
        self.node_descriptions: Dict[str, str] = {}
        self._cache_loaded = False
        self._lock = threading.Lock()
    
    def parse_chunk(self, chunk: str, chunk_type: str) -> Dict:
        """Parse a specific section of SMDB data"""
        results = {'links': {}, 'nodes': {}}
        
        if chunk_type == 'NODES':
            for line in chunk.split('\n'):
                line = line.strip()
                if line.startswith('0x') and ',' in line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 8:
                        node_guid = parts[1]
                        node_desc = parts[7].strip('"')
                        results['nodes'][node_guid] = node_desc
        
        elif chunk_type == 'LINKS':
            for line in chunk.split('\n'):
                line = line.strip()
                if line.startswith('0x') and ',' in line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 4:
                        try:
                            guid1, port1 = parts[0], int(parts[1])
                            guid2, port2 = parts[2], int(parts[3])
                            results['links'][(guid1, port1)] = (guid2, port2)
                            results['links'][(guid2, port2)] = (guid1, port1)
                        except ValueError:
                            continue
        
        return results
    
    def parse_parallel(self, smdb_file: Path) -> bool:
        """Parse SMDB file using parallel processing"""
        if not smdb_file.exists():
            return False
        
        try:
            # Read and split file into sections
            with gzip.open(smdb_file, 'rt', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find section boundaries
            nodes_start = content.find("SystemImageGUID, NodeGUID, NodeType")
            nodes_end = content.find("END_NODES")
            links_start = content.find("NodeGUID1, PortNum1, NodeGUID2, PortNum2")
            links_end = content.find("END_LINKS")
            
            chunks = []
            if nodes_start != -1 and nodes_end != -1:
                chunks.append((content[nodes_start:nodes_end], 'NODES'))
            if links_start != -1 and links_end != -1:
                chunks.append((content[links_start:links_end], 'LINKS'))
            
            # Process chunks in parallel
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self.parse_chunk, chunk, chunk_type) 
                          for chunk, chunk_type in chunks]
                
                for future in as_completed(futures):
                    result = future.result()
                    self.node_descriptions.update(result['nodes'])
                    self.links.update(result['links'])
            
            self._cache_loaded = True
            return True
            
        except Exception as e:
            print(f"Error parsing SMDB file: {e}")
            return False
    
    def get_link_partner(self, guid: str, port: int) -> Optional[Tuple[str, int]]:
        return self.links.get((guid, port))
    
    def get_node_description(self, guid: str) -> str:
        return self.node_descriptions.get(guid, "Unknown")
    
    def classify_port_type(self, guid: str, port: int) -> str:
        partner = self.get_link_partner(guid, port)
        if not partner:
            return "unknown"
        
        partner_guid, partner_port = partner
        partner_desc = self.get_node_description(partner_guid)
        
        # Check if partner is a GPU (contains HCA or GPU keywords)
        if any(keyword in partner_desc.upper() for keyword in ['HCA', 'GPU', 'DGX']):
            return "access"
        else:
            return "trunk"

class FastLogProcessor:
    """High-performance log processor with streaming and parallel processing"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(8, mp.cpu_count())
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Pre-compile regex patterns for better performance"""
        return {
            'trunk_failure': re.compile(
                r'\[([^]]+)\].*Trunk port failure detected for switch GUID (0x[a-fA-F0-9]+).*port number (\d+)'
            ),
            'port_down': re.compile(
                r'\[([^]]+)\].*fabric manager received port down event on switch with GUID (0x[a-fA-F0-9]+).*port num (\d+)'
            ),
            'gpu_nvl_start': re.compile(
                r'\[([^]]+)\].*Fabric Manager detected GPU NVL Non Fatal error on'
            ),
            'nvlsm_state': re.compile(
                r'([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}).*Switch (0x[a-fA-F0-9]+).*port (\d+)\(\d+\) changed state from (\w+) to (\w+)'
            )
        }
    
    def process_file_chunk(self, file_path: Path, start_byte: int, chunk_size: int, 
                          log_type: str) -> List:
        """Process a chunk of a log file"""
        events = []
        
        try:
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                f.seek(start_byte)
                chunk = f.read(chunk_size)
                
                if log_type == 'fabricmanager':
                    events.extend(self._parse_fm_chunk(chunk, str(file_path)))
                elif log_type == 'nvlsm':
                    events.extend(self._parse_nvlsm_chunk(chunk, str(file_path)))
                    
        except Exception as e:
            print(f"Error processing chunk from {file_path}: {e}")
        
        return events
    
    def _parse_fm_chunk(self, chunk: str, source_file: str) -> List:
        """Parse fabric manager log chunk"""
        events = []
        lines = chunk.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Trunk failures
            match = self.patterns['trunk_failure'].search(line)
            if match:
                try:
                    timestamp = self._parse_timestamp(match.group(1))
                    events.append({
                        'type': 'trunk_failure',
                        'timestamp': timestamp,
                        'switch_guid': match.group(2),
                        'port': int(match.group(3)),
                        'source': source_file
                    })
                except (ValueError, IndexError):
                    pass
                i += 1
                continue
            
            # Port down events
            match = self.patterns['port_down'].search(line)
            if match:
                try:
                    timestamp = self._parse_timestamp(match.group(1))
                    events.append({
                        'type': 'port_down',
                        'timestamp': timestamp,
                        'switch_guid': match.group(2),
                        'port': int(match.group(3)),
                        'source': source_file
                    })
                except (ValueError, IndexError):
                    pass
                i += 1
                continue
            
            # GPU NVL errors (multi-line parsing)
            match = self.patterns['gpu_nvl_start'].search(line)
            if match:
                gpu_error = self._parse_gpu_nvl_error_multiline(lines, i, source_file)
                if gpu_error:
                    events.append(gpu_error)
                i += 1
                continue
            
            i += 1
        
        return events
    
    def _parse_gpu_nvl_error_multiline(self, lines: List[str], start_idx: int, source_file: str) -> Optional[Dict]:
        """Parse multi-line GPU NVL error starting from start_idx"""
        try:
            # Parse the header line
            header_line = lines[start_idx]
            timestamp_match = re.search(r'\[([^]]+)\]', header_line)
            if not timestamp_match:
                return None
            
            timestamp = self._parse_timestamp(timestamp_match.group(1))
            
            # Look for detailed error information in subsequent lines
            error_details = {}
            for i in range(start_idx + 1, min(start_idx + 20, len(lines))):
                line = lines[i].strip()
                if not line or 'Fabric Manager detected' in line:
                    break
                
                # Parse key-value pairs
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        
                        # Map common fields
                        if 'gpuGuid' in key:
                            error_details['gpu_guid'] = value
                        elif 'switchGuid' in key:
                            error_details['switch_guid'] = value
                        elif 'switchInstance' in key:
                            error_details['switch_instance'] = int(value) if value.isdigit() else 0
                        elif 'gpuInstance' in key:
                            error_details['gpu_instance'] = int(value) if value.isdigit() else 0
                        elif 'partitionId' in key:
                            error_details['partition_id'] = int(value) if value.isdigit() else 0
                        elif 'nvlLink' in key:
                            error_details['nvl_link'] = int(value) if value.isdigit() else 0
                        elif 'linkId' in key:
                            error_details['link_id'] = int(value) if value.isdigit() else 0
                        elif 'errorCode' in key:
                            error_details['error_code'] = value
                        elif 'errorSubcode' in key:
                            error_details['error_subcode'] = value
                        elif 'errorData' in key:
                            error_details['error_data'] = value
                        elif 'portNum' in key:
                            error_details['port_num'] = int(value) if value.isdigit() else None
            
            # Create GPU NVL error event
            return {
                'type': 'gpu_nvl_error',
                'timestamp': timestamp,
                'gpu_guid': error_details.get('gpu_guid', 'Unknown'),
                'switch_guid': error_details.get('switch_guid', 'Unknown'),
                'port_num': error_details.get('port_num'),
                'error_code': error_details.get('error_code', '0x00'),
                'error_subcode': error_details.get('error_subcode', '0x00'),
                'error_data': error_details.get('error_data', ''),
                'switch_instance': error_details.get('switch_instance', 0),
                'gpu_instance': error_details.get('gpu_instance', 0),
                'partition_id': error_details.get('partition_id', 0),
                'nvl_link': error_details.get('nvl_link', 0),
                'link_id': error_details.get('link_id', 0),
                'source': source_file
            }
            
        except Exception as e:
            return None
    
    def _parse_nvlsm_chunk(self, chunk: str, source_file: str) -> List:
        """Parse nvlsm log chunk"""
        events = []
        lines = chunk.split('\n')
        
        for line in lines:
            match = self.patterns['nvlsm_state'].search(line)
            if match and match.group(5) == 'DOWN':
                try:
                    timestamp = self._parse_nvlsm_timestamp(match.group(1))
                    events.append({
                        'type': 'nvlsm_state',
                        'timestamp': timestamp,
                        'switch_guid': match.group(2),
                        'port': int(match.group(3)),
                        'state_from': match.group(4),
                        'state_to': match.group(5),
                        'source': source_file
                    })
                except (ValueError, IndexError):
                    continue
        
        return events
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse fabric manager timestamp"""
        try:
            return datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
        except ValueError:
            try:
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return datetime.now()
    
    def _parse_nvlsm_timestamp(self, timestamp_str: str) -> datetime:
        """Parse nvlsm timestamp"""
        try:
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def get_file_chunks(self, file_path: Path, chunk_size: int = 10*1024*1024) -> List[Tuple[int, int]]:
        """Split file into chunks for parallel processing"""
        chunks = []
        
        try:
            file_size = file_path.stat().st_size
            start = 0
            
            while start < file_size:
                end = min(start + chunk_size, file_size)
                chunks.append((start, end - start))
                start = end
                
        except Exception as e:
            print(f"Error getting file chunks for {file_path}: {e}")
        
        return chunks
    
    def process_files_parallel(self, files: List[Path], log_type: str) -> List:
        """Process multiple files in parallel"""
        all_events = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # For large files, split into chunks
            chunk_futures = []
            
            for file_path in files:
                file_size = file_path.stat().st_size
                
                if file_size > 50 * 1024 * 1024:  # Files larger than 50MB
                    chunks = self.get_file_chunks(file_path)
                    for start, size in chunks:
                        future = executor.submit(
                            self.process_file_chunk, file_path, start, size, log_type
                        )
                        chunk_futures.append(future)
                else:
                    # Process small files as single chunks
                    future = executor.submit(
                        self.process_file_chunk, file_path, 0, file_size, log_type
                    )
                    chunk_futures.append(future)
            
            # Collect results
            for future in as_completed(chunk_futures):
                try:
                    events = future.result()
                    all_events.extend(events)
                except Exception as e:
                    print(f"Error processing file chunk: {e}")
        
        return all_events

class FastNMXTableAnalyzer:
    """High-performance NMX-C Table Analyzer"""
    
    def __init__(self, nmx_dir: str, max_workers: int = None):
        self.nmx_dir = Path(nmx_dir)
        self.max_workers = max_workers or min(8, mp.cpu_count())
        self.log_processor = FastLogProcessor(max_workers)
        self.smdb_parser = FastSMDBParser()
        self.trunk_events: List[TrunkFailureEvent] = []
        self.correlation_cache: Dict[str, List] = defaultdict(list)
        
        print(f"Initialized with {self.max_workers} workers")
    
    def discover_log_files(self) -> Dict[str, List[Path]]:
        """Discover all log files with smart filtering"""
        files = {
            'fabricmanager': [],
            'nvlsm': [],
            'smdb': []
        }
        
        # Use glob patterns for faster discovery
        for pattern, key in [
            ('fabricmanager*.log*.gz', 'fabricmanager'),
            ('nvlsm*.log*.gz', 'nvlsm'),
            ('dumps/nvlsm-smdb.dump.gz', 'smdb')
        ]:
            found_files = list(self.nmx_dir.glob(pattern))
            if key == 'smdb':
                files[key] = found_files[:1]  # Only need one SMDB file
            else:
                # Sort by modification time for better processing order
                found_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                files[key] = found_files[:10]  # Limit to 10 most recent
        
        return files
    
    def run_analysis(self) -> int:
        """Run high-performance analysis"""
        start_time = time.time()
        
        # Discover files
        files = self.discover_log_files()
        total_files = sum(len(f) for f in files.values())
        print(f"Found {total_files} files to process")
        
        if not files['fabricmanager'] and not files['nvlsm']:
            print("No log files found")
            return 0
        
        # Parse SMDB in parallel
        if files['smdb']:
            print("Parsing SMDB file...")
            smdb_start = time.time()
            self.smdb_parser.parse_parallel(files['smdb'][0])
            print(f"SMDB parsed in {time.time() - smdb_start:.2f}s")
        
        # Process all log types in parallel
        print("Processing log files in parallel...")
        process_start = time.time()
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            if files['fabricmanager']:
                future = executor.submit(
                    self.log_processor.process_files_parallel,
                    files['fabricmanager'], 'fabricmanager'
                )
                futures.append(('fabricmanager', future))
            
            if files['nvlsm']:
                future = executor.submit(
                    self.log_processor.process_files_parallel,
                    files['nvlsm'], 'nvlsm'
                )
                futures.append(('nvlsm', future))
            
            # Collect results
            raw_events = {'fabricmanager': [], 'nvlsm': []}
            for log_type, future in futures:
                try:
                    events = future.result()
                    raw_events[log_type] = events
                    print(f"Processed {len(events)} {log_type} events")
                except Exception as e:
                    print(f"Error processing {log_type}: {e}")
        
        print(f"Log processing completed in {time.time() - process_start:.2f}s")
        
        # Correlate events
        print("Correlating events...")
        correlate_start = time.time()
        self._correlate_events_fast(raw_events)
        print(f"Correlation completed in {time.time() - correlate_start:.2f}s")
        
        total_time = time.time() - start_time
        print(f"Total analysis time: {total_time:.2f}s")
        print(f"Processed {len(self.trunk_events)} correlated events")
        
        return len(self.trunk_events)
    
    def _correlate_events_fast(self, raw_events: Dict[str, List]):
        """Fast event correlation using time-based indexing"""
        # Create time-indexed lookup for fast correlation
        nvlsm_index = defaultdict(list)
        for event in raw_events['nvlsm']:
            time_key = event['timestamp'].replace(second=0, microsecond=0)
            nvlsm_index[time_key].append(event)
        
        # Create GPU error index for correlation
        gpu_error_index = defaultdict(list)
        gpu_errors = [e for e in raw_events['fabricmanager'] if e['type'] == 'gpu_nvl_error']
        for gpu_event in gpu_errors:
            time_key = gpu_event['timestamp'].replace(second=0, microsecond=0)
            gpu_error_index[time_key].append(gpu_event)
        
        # Process fabricmanager events and correlate
        for fm_event in raw_events['fabricmanager']:
            if fm_event['type'] == 'gpu_nvl_error':
                continue  # Skip GPU errors here, they'll be correlated with trunk events
            
            # Create TrunkFailureEvent or PortDownEvent
            if fm_event['type'] == 'trunk_failure':
                event = TrunkFailureEvent(
                    timestamp=fm_event['timestamp'],
                    switch_guid=fm_event['switch_guid'],
                    switch_name=f"Switch-{fm_event['switch_guid'][-8:]}",
                    port=fm_event['port'],
                    cage=0, slot=0,
                    state_from="UNKNOWN", state_to="DOWN",
                    chassis_sn="Unknown", partition_id=None, tid=0,
                    fm_source=Path(fm_event['source']).name
                )
            else:  # port_down
                event = TrunkFailureEvent(
                    timestamp=fm_event['timestamp'],
                    switch_guid=fm_event['switch_guid'],
                    switch_name=f"Switch-{fm_event['switch_guid'][-8:]}",
                    port=fm_event['port'],
                    cage=0, slot=0,
                    state_from="UNKNOWN", state_to="DOWN",
                    chassis_sn="Unknown", partition_id=None, tid=0,
                    fm_source=Path(fm_event['source']).name,
                    event_type="port_down"
                )
            
            # Fast correlation with nvlsm events
            time_window = timedelta(seconds=10)
            for delta in [0, -1, 1]:  # Check current minute and adjacent minutes
                check_time = fm_event['timestamp'].replace(second=0, microsecond=0) + timedelta(minutes=delta)
                
                for nvl_event in nvlsm_index.get(check_time, []):
                    if (nvl_event['switch_guid'] == fm_event['switch_guid'] and
                        nvl_event['port'] == fm_event['port'] and
                        abs((nvl_event['timestamp'] - fm_event['timestamp']).total_seconds()) <= time_window.total_seconds()):
                        
                        event.sm_source = Path(nvl_event['source']).name
                        event.state_from = nvl_event['state_from']
                        event.state_to = nvl_event['state_to']
                        break
            
            # Correlate with GPU NVL errors (5-second window)
            gpu_time_window = timedelta(seconds=5)
            for delta in [0, -1, 1]:
                check_time = fm_event['timestamp'].replace(second=0, microsecond=0) + timedelta(minutes=delta)
                
                for gpu_event in gpu_error_index.get(check_time, []):
                    if (gpu_event['switch_guid'] == fm_event['switch_guid'] and
                        gpu_event['port_num'] == fm_event['port'] and
                        abs((gpu_event['timestamp'] - fm_event['timestamp']).total_seconds()) <= gpu_time_window.total_seconds()):
                        
                        # Create GPUNVLError object with XID mapping
                        gpu_error_obj = GPUNVLError(
                            timestamp=gpu_event['timestamp'],
                            gpu_guid=gpu_event['gpu_guid'],
                            port_num=gpu_event['port_num'],
                            error_timestamp=gpu_event['timestamp'],
                            severity="Non Fatal",
                            switch_guid=gpu_event['switch_guid'],
                            switch_instance=gpu_event['switch_instance'],
                            gpu_instance=gpu_event['gpu_instance'],
                            partition_id=gpu_event['partition_id'],
                            nvl_link=gpu_event['nvl_link'],
                            link_id=gpu_event['link_id'],
                            error_code=gpu_event['error_code'],
                            error_subcode=gpu_event['error_subcode'],
                            error_data=gpu_event['error_data'],
                            source_file=Path(gpu_event['source']).name
                        )
                        
                        event.associated_gpu_errors.append(gpu_error_obj)
            
            # Add link partner information
            if self.smdb_parser._cache_loaded:
                partner = self.smdb_parser.get_link_partner(event.switch_guid, event.port)
                if partner:
                    event.link_partner_guid, event.link_partner_port = partner
                    event.port_type = self.smdb_parser.classify_port_type(event.switch_guid, event.port)
            
            self.trunk_events.append(event)
    
    def generate_table_report(self, output_file: str = "fast_analysis.txt"):
        """Generate optimized table report"""
        print(f"Generating report: {output_file}")
        
        # Group link partners for efficient display
        groups = self._group_link_partners_fast()
        
        with open(output_file, 'w') as f:
            f.write("FAST NMX-C ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Performance summary
            access_count = sum(1 for e in self.trunk_events if e.port_type == "access")
            trunk_count = sum(1 for e in self.trunk_events if e.port_type == "trunk")
            
            f.write(f"Performance Summary:\n")
            f.write(f"  Total Events: {len(self.trunk_events)}\n")
            f.write(f"  Access Ports: {access_count}\n")
            f.write(f"  Trunk Ports: {trunk_count}\n")
            f.write(f"  Workers Used: {self.max_workers}\n\n")
            
            # Table header  
            header = (
                f"{'#':<3} {'Timestamp':<19} {'Switch/GPU GUID':<18} {'Port':<4} {'Type':<6} "
                f"{'Event/Error':<12} {'Details':<25} {'XID/Partner':<30} {'Detected In':<15}\n"
            )
            f.write(header)
            f.write("-" * 132 + "\n")
            
            # Write events
            for i, group in enumerate(groups, 1):
                for j, event in enumerate(group):
                    # Format partner info
                    if event.link_partner_guid:
                        partner_guid_short = event.link_partner_guid[-8:]
                        partner_desc = self.smdb_parser.get_node_description(event.link_partner_guid)
                        if ";" in partner_desc:
                            partner_desc_short = partner_desc.split(";")[-1].split(":")[0][:15]
                        else:
                            partner_desc_short = partner_desc[:15]
                        partner_info = f"{partner_guid_short}:{event.link_partner_port} ({partner_desc_short})"
                    else:
                        partner_info = "Unknown"
                    
                    # Format sources
                    fm_src = event.fm_source[:3] if event.fm_source else "---"
                    sm_src = event.sm_source[:3] if event.sm_source else "---"
                    sources = f"{fm_src}/{sm_src}"
                    
                    incident_id = f"{i}" if j == 0 else ""
                    switch_guid_short = event.switch_guid[-8:]
                    state_change = f"{event.state_from}→{event.state_to}"
                    port_type = event.port_type.title()[:6]
                    switch_name_short = event.switch_name.split(';')[-1][:25] if ';' in event.switch_name else event.switch_name[:25]
                    
                    line = (
                        f"{incident_id:<3} {event.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<19} "
                        f"{switch_guid_short:<18} {event.port:<4} {port_type:<6} "
                        f"{state_change:<12} {switch_name_short:<25} {partner_info:<30} {sources:<15}\n"
                    )
                    f.write(line)
                    
                    # Add associated GPU NVL errors as indented sub-entries
                    if event.associated_gpu_errors:
                        for gpu_error in event.associated_gpu_errors:
                            error_time_str = gpu_error.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                            error_code_str = f"{gpu_error.error_code}/{gpu_error.error_subcode}" if gpu_error.error_code and gpu_error.error_subcode else "N/A"
                            equivalent_xid_str = f"XID-{gpu_error.equivalent_xid}" if gpu_error.equivalent_xid else "N/A"
                            gpu_guid_short = gpu_error.gpu_guid[-8:] if gpu_error.gpu_guid else "N/A"
                            severity_short = gpu_error.severity.replace(" ", "")[:8]  # "NonFatal" or "Fatal"
                            
                            # Indented sub-line for GPU error
                            gpu_line = (
                                f"{'├─':<3} {error_time_str:<19} "
                                f"GPU:{gpu_guid_short:<13} {gpu_error.port_num or 'N/A':<4} {'GPU':<4} "
                                f"{severity_short:<12} {error_code_str:<25} {equivalent_xid_str:<30} {gpu_error.resolution or 'N/A':<15}\n"
                            )
                            f.write(gpu_line)
                
                if len(group) > 1:
                    f.write("\n")
        
        print(f"Report written to: {output_file}")
    
    def _group_link_partners_fast(self) -> List[List[TrunkFailureEvent]]:
        """Fast link partner grouping using hash-based approach"""
        groups = []
        processed = set()
        
        # Create hash-based lookup for O(1) partner finding
        event_lookup = {}
        for event in self.trunk_events:
            key = (event.switch_guid, event.port)
            if key not in event_lookup:
                event_lookup[key] = []
            event_lookup[key].append(event)
        
        for event in self.trunk_events:
            event_id = id(event)
            if event_id in processed:
                continue
            
            group = [event]
            processed.add(event_id)
            
            # Find link partner
            if event.link_partner_guid and event.link_partner_port:
                partner_key = (event.link_partner_guid, event.link_partner_port)
                partner_events = event_lookup.get(partner_key, [])
                
                for partner_event in partner_events:
                    partner_id = id(partner_event)
                    if (partner_id not in processed and
                        abs((partner_event.timestamp - event.timestamp).total_seconds()) <= 300):
                        group.append(partner_event)
                        processed.add(partner_id)
                        break
            
            groups.append(group)
        
        return groups

def main():
    """Main entry point for fast analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Fast Multi-threaded NMX-C Analyzer",
        epilog="Optimized for large directories with multiple rotated log files"
    )
    parser.add_argument("--nmx-dir", "-d", default=".",
                       help="Path to nmx-c directory")
    parser.add_argument("--output", "-o", default="fast_analysis.txt",
                       help="Output file")
    parser.add_argument("--workers", "-w", type=int,
                       help="Number of worker threads (default: auto)")
    parser.add_argument("--benchmark", "-b", action="store_true",
                       help="Show detailed performance metrics")
    
    args = parser.parse_args()
    
    if not Path(args.nmx_dir).exists():
        print(f"Error: Directory not found: {args.nmx_dir}")
        return 1
    
    # Initialize analyzer
    analyzer = FastNMXTableAnalyzer(args.nmx_dir, max_workers=args.workers)
    
    # Run analysis with timing
    start_time = time.time()
    event_count = analyzer.run_analysis()
    analysis_time = time.time() - start_time
    
    if event_count == 0:
        print("No events found to analyze")
        return 1
    
    # Generate report
    report_start = time.time()
    analyzer.generate_table_report(args.output)
    report_time = time.time() - report_start
    
    # Performance summary
    total_time = analysis_time + report_time
    print(f"\nPerformance Summary:")
    print(f"  Analysis: {analysis_time:.2f}s")
    print(f"  Report:   {report_time:.2f}s")
    print(f"  Total:    {total_time:.2f}s")
    print(f"  Events/s: {event_count/analysis_time:.1f}")
    
    if args.benchmark:
        print(f"\nBenchmark Details:")
        print(f"  Workers:     {analyzer.max_workers}")
        print(f"  CPU Cores:   {mp.cpu_count()}")
        print(f"  Events:      {event_count}")
        print(f"  Throughput:  {event_count/total_time:.1f} events/sec")
    
    return 0

if __name__ == "__main__":
    exit(main()) 