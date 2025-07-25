# NMX-C Analyzer Performance Optimizations

## Overview
For large directories with multiple rotated log files, the analyzer can be significantly optimized using several techniques:

## 1. Multi-Threading Optimizations

### A. Parallel File Processing
```python
# Process multiple log files simultaneously
with ThreadPoolExecutor(max_workers=8) as executor:
    futures = []
    for log_file in log_files:
        future = executor.submit(process_log_file, log_file)
        futures.append(future)
```

### B. Chunked File Processing
```python
# Split large files into chunks for parallel processing
def process_large_file(file_path, chunk_size=10*1024*1024):
    file_size = file_path.stat().st_size
    chunks = [(start, min(chunk_size, file_size - start)) 
              for start in range(0, file_size, chunk_size)]
    
    with ThreadPoolExecutor() as executor:
        results = executor.map(lambda chunk: process_chunk(file_path, *chunk), chunks)
```

## 2. Memory Optimizations

### A. Streaming Processing
- Process files line-by-line instead of loading entire files
- Use generators for large datasets
- Implement memory-mapped file access for very large files

### B. Smart Caching
```python
# Cache compiled regex patterns
patterns = {
    'trunk_failure': re.compile(r'pattern1'),
    'port_down': re.compile(r'pattern2')
}

# Cache SMDB lookups
link_cache = {}
node_cache = {}
```

## 3. I/O Optimizations

### A. Asynchronous File Operations
```python
import asyncio
import aiofiles

async def process_file_async(file_path):
    async with aiofiles.open(file_path, 'r') as f:
        async for line in f:
            # Process line
            pass
```

### B. Efficient File Discovery
```python
# Use glob patterns instead of walking directory trees
fabricmanager_files = list(Path(nmx_dir).glob('fabricmanager*.log*.gz'))
nvlsm_files = list(Path(nmx_dir).glob('nvlsm*.log*.gz'))
```

## 4. Algorithm Optimizations

### A. Time-Based Indexing for Correlation
```python
# Create time-indexed lookup for O(1) correlation
from collections import defaultdict

time_index = defaultdict(list)
for event in events:
    time_key = event.timestamp.replace(second=0, microsecond=0)
    time_index[time_key].append(event)
```

### B. Hash-Based Partner Lookup
```python
# O(1) partner lookup instead of O(n) search
partner_lookup = {}
for event in events:
    key = (event.switch_guid, event.port)
    partner_lookup[key] = event
```

## 5. Data Structure Optimizations

### A. Use Dataclasses with Slots
```python
from dataclasses import dataclass

@dataclass
class Event:
    __slots__ = ['timestamp', 'switch_guid', 'port', 'state']
    timestamp: datetime
    switch_guid: str
    port: int
    state: str
```

### B. Efficient Collections
```python
from collections import deque, defaultdict
import bisect

# Use deque for frequent append/pop operations
event_queue = deque()

# Use defaultdict to avoid key checking
events_by_switch = defaultdict(list)

# Use bisect for sorted insertions
bisect.insort(sorted_events, new_event)
```

## 6. Practical Usage Examples

### Basic Multi-threaded Processing
```bash
# Use the fast analyzer with 8 worker threads
python3 nmx_table_analyzer_fast.py --nmx-dir /path/to/large/dir --workers 8

# Enable benchmarking to see performance metrics
python3 nmx_table_analyzer_fast.py --nmx-dir /path/to/large/dir --benchmark
```

### Batch Processing Large Directories
```bash
# Process multiple directories with optimizations
python3 batch_analyze_fast.py --base-dir /path/to/flattened_nmx_c --workers 12 --timeout 30
```

## 7. Performance Metrics

### Expected Improvements
- **File Processing**: 3-5x faster with parallel processing
- **Memory Usage**: 50-70% reduction with streaming
- **Correlation**: 10-20x faster with indexed lookups
- **Overall**: 2-4x total performance improvement

### Benchmarking
```python
# Measure performance
import time

start = time.time()
events = process_logs_parallel(log_files)
processing_time = time.time() - start

start = time.time()
correlate_events_fast(events)
correlation_time = time.time() - start

print(f"Processing: {processing_time:.2f}s")
print(f"Correlation: {correlation_time:.2f}s")
print(f"Events/sec: {len(events)/processing_time:.1f}")
```

## 8. Hardware Considerations

### Optimal Configuration
- **CPU**: Multi-core systems benefit most (8+ cores recommended)
- **Memory**: 8GB+ for large datasets
- **Storage**: SSD storage significantly improves I/O performance
- **Network**: For remote file access, consider local caching

### Scaling Guidelines
```python
# Auto-detect optimal worker count
import multiprocessing as mp

optimal_workers = min(
    mp.cpu_count(),           # Don't exceed CPU cores
    len(log_files),           # Don't exceed file count
    8                         # Cap at 8 for I/O bound tasks
)
```

## 9. Monitoring and Profiling

### Performance Monitoring
```python
import psutil
import time

def monitor_performance():
    process = psutil.Process()
    
    while processing:
        cpu_percent = process.cpu_percent()
        memory_mb = process.memory_info().rss / 1024 / 1024
        print(f"CPU: {cpu_percent}%, Memory: {memory_mb:.1f}MB")
        time.sleep(1)
```

### Profiling Bottlenecks
```python
import cProfile
import pstats

# Profile the analyzer
cProfile.run('analyzer.run_analysis()', 'profile_stats')
stats = pstats.Stats('profile_stats')
stats.sort_stats('cumulative').print_stats(20)
```

## 10. Error Handling and Resilience

### Graceful Degradation
```python
def process_file_safe(file_path):
    try:
        return process_file(file_path)
    except Exception as e:
        print(f"Warning: Failed to process {file_path}: {e}")
        return []  # Return empty result instead of crashing

# Use with concurrent.futures for resilient parallel processing
with ThreadPoolExecutor() as executor:
    results = [future.result() for future in 
               as_completed([executor.submit(process_file_safe, f) for f in files])]
```

## 11. Configuration Recommendations

### Small Datasets (< 100MB)
```bash
python3 nmx_table_analyzer.py --nmx-dir /path/to/small/dir
```

### Medium Datasets (100MB - 1GB)
```bash
python3 nmx_table_analyzer_fast.py --nmx-dir /path/to/medium/dir --workers 4
```

### Large Datasets (> 1GB)
```bash
python3 nmx_table_analyzer_fast.py --nmx-dir /path/to/large/dir --workers 8 --benchmark
```

### Batch Processing
```bash
python3 batch_analyze_fast.py --base-dir /path/to/all/dirs --workers 12 --timeout 60 --include-large
``` 