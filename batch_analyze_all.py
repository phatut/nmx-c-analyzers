#!/usr/bin/env python3
"""
Batch Analysis Script for NMX-C Folders
Runs the enhanced analyzer on all nmx-c folders and saves results in each folder.
"""

import os
import sys
import subprocess
import time
from pathlib import Path
from datetime import datetime


def run_analysis_on_folder(folder_path: Path, analyzer_script: Path) -> dict:
    """Run analysis on a single nmx-c folder"""
    folder_name = folder_path.name
    print(f"\n{'='*60}")
    print(f"ANALYZING: {folder_name}")
    print(f"{'='*60}")
    
    # Output files in the same folder
    table_output = folder_path / f"{folder_name}_analysis_table.txt"
    csv_output = folder_path / f"{folder_name}_analysis.csv"
    
    # Build command
    cmd = [
        sys.executable, str(analyzer_script),
        "--nmx-dir", str(folder_path),
        "--output", str(table_output),
        "--csv", str(csv_output)
    ]
    
    try:
        start_time = time.time()
        print(f"Running: {' '.join(cmd)}")
        
        # Run the analyzer
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300  # 5 minute timeout
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        if result.returncode == 0:
            print(f"SUCCESS: Analysis completed in {duration:.2f} seconds")
            
            # Parse results from stdout
            output_lines = result.stdout.strip().split('\n')
            summary = {
                'status': 'success',
                'duration': duration,
                'events_analyzed': 0,
                'access_ports': 0,
                'trunk_ports': 0,
                'legacy_ports': 0,
                'gpu_errors': 0,
                'table_file': str(table_output),
                'csv_file': str(csv_output)
            }
            
            # Extract metrics from output
            for line in output_lines:
                if 'Events analyzed:' in line:
                    try:
                        summary['events_analyzed'] = int(line.split(':')[1].strip())
                    except:
                        pass
                elif 'Port breakdown:' in line:
                    try:
                        # Parse "Port breakdown: X access, Y trunk, Z legacy"
                        parts = line.split(':')[1].strip().split(',')
                        for part in parts:
                            part = part.strip()
                            if 'access' in part:
                                summary['access_ports'] = int(part.split()[0])
                            elif 'trunk' in part:
                                summary['trunk_ports'] = int(part.split()[0])
                            elif 'legacy' in part:
                                summary['legacy_ports'] = int(part.split()[0])
                    except:
                        pass
                elif 'GPU errors found:' in line:
                    try:
                        summary['gpu_errors'] = int(line.split(':')[1].strip())
                    except:
                        pass
            
            print(f"   Events: {summary['events_analyzed']}")
            print(f"   Access ports: {summary['access_ports']}")
            print(f"   Trunk ports: {summary['trunk_ports']}")
            print(f"   Legacy ports: {summary['legacy_ports']}")
            print(f"   GPU errors: {summary['gpu_errors']}")
            print(f"   Table: {table_output.name}")
            print(f"   CSV: {csv_output.name}")
            
            return summary
            
        else:
            print(f"FAILED: Return code {result.returncode}")
            print(f"   Error: {result.stderr}")
            return {
                'status': 'failed',
                'duration': duration,
                'error': result.stderr,
                'return_code': result.returncode
            }
            
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT: Analysis exceeded 5 minutes")
        return {
            'status': 'timeout',
            'duration': 300,
            'error': 'Analysis timeout'
        }
    except Exception as e:
        print(f"EXCEPTION: {str(e)}")
        return {
            'status': 'exception',
            'duration': 0,
            'error': str(e)
        }


def main():
    """Main batch analysis function"""
    print("NMX-C BATCH ANALYSIS TOOL")
    print("=" * 60)
    
    # Paths
    script_dir = Path(__file__).parent
    analyzer_script = script_dir / "nmx_table_analyzer.py"
    flattened_dir = script_dir.parent / "Downloads" / "flattened_nmx_c"
    
    # Verify paths
    if not analyzer_script.exists():
        print(f"ERROR: Analyzer script not found: {analyzer_script}")
        return 1
        
    if not flattened_dir.exists():
        print(f"ERROR: Data directory not found: {flattened_dir}")
        return 1
    
    # Find all nmx-c folders
    nmx_folders = sorted([f for f in flattened_dir.iterdir() 
                         if f.is_dir() and f.name.startswith('nmx-c-')])
    
    if not nmx_folders:
        print(f"ERROR: No nmx-c folders found in {flattened_dir}")
        return 1
    
    print(f"Found {len(nmx_folders)} folders to analyze")
    print(f"Using analyzer: {analyzer_script}")
    print(f"Data directory: {flattened_dir}")
    
    # Run analysis on all folders
    results = {}
    total_start_time = time.time()
    
    for i, folder in enumerate(nmx_folders, 1):
        print(f"\n[{i}/{len(nmx_folders)}] Processing {folder.name}...")
        results[folder.name] = run_analysis_on_folder(folder, analyzer_script)
    
    total_duration = time.time() - total_start_time
    
    # Generate summary report
    print(f"\n{'='*80}")
    print("BATCH ANALYSIS SUMMARY")
    print(f"{'='*80}")
    print(f"Total time: {total_duration:.2f} seconds ({total_duration/60:.1f} minutes)")
    print(f"Folders processed: {len(nmx_folders)}")
    
    # Count results by status
    successful = sum(1 for r in results.values() if r.get('status') == 'success')
    failed = sum(1 for r in results.values() if r.get('status') == 'failed')
    timeouts = sum(1 for r in results.values() if r.get('status') == 'timeout')
    exceptions = sum(1 for r in results.values() if r.get('status') == 'exception')
    
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Timeouts: {timeouts}")
    print(f"Exceptions: {exceptions}")
    
    # Aggregate statistics from successful runs
    if successful > 0:
        total_events = sum(r.get('events_analyzed', 0) for r in results.values() if r.get('status') == 'success')
        total_access = sum(r.get('access_ports', 0) for r in results.values() if r.get('status') == 'success')
        total_trunk = sum(r.get('trunk_ports', 0) for r in results.values() if r.get('status') == 'success')
        total_legacy = sum(r.get('legacy_ports', 0) for r in results.values() if r.get('status') == 'success')
        total_gpu_errors = sum(r.get('gpu_errors', 0) for r in results.values() if r.get('status') == 'success')
        
        print(f"\nAGGREGATE STATISTICS:")
        print(f"   Total events: {total_events:,}")
        print(f"   Total access ports: {total_access:,}")
        print(f"   Total trunk ports: {total_trunk:,}")
        print(f"   Total legacy ports: {total_legacy:,}")
        print(f"   Total GPU errors: {total_gpu_errors:,}")
    
    # Show failed analyses
    if failed > 0 or timeouts > 0 or exceptions > 0:
        print(f"\nFAILED ANALYSES:")
        for folder_name, result in results.items():
            if result.get('status') != 'success':
                status = result.get('status', 'unknown')
                error = result.get('error', 'Unknown error')
                print(f"   {folder_name}: {status.upper()} - {error}")
    
    # Save detailed results
    summary_file = script_dir / f"batch_analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(summary_file, 'w') as f:
        f.write(f"NMX-C Batch Analysis Summary\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"=" * 60 + "\n\n")
        
        for folder_name, result in results.items():
            f.write(f"Folder: {folder_name}\n")
            f.write(f"Status: {result.get('status', 'unknown')}\n")
            if result.get('status') == 'success':
                f.write(f"Duration: {result.get('duration', 0):.2f}s\n")
                f.write(f"Events: {result.get('events_analyzed', 0)}\n")
                f.write(f"Access ports: {result.get('access_ports', 0)}\n")
                f.write(f"Trunk ports: {result.get('trunk_ports', 0)}\n")
                f.write(f"Legacy ports: {result.get('legacy_ports', 0)}\n")
                f.write(f"GPU errors: {result.get('gpu_errors', 0)}\n")
                f.write(f"Table file: {result.get('table_file', 'N/A')}\n")
                f.write(f"CSV file: {result.get('csv_file', 'N/A')}\n")
            else:
                f.write(f"Error: {result.get('error', 'Unknown')}\n")
            f.write("\n")
    
    print(f"\nDetailed summary saved to: {summary_file}")
    print(f"\nBatch analysis complete!")
    
    return 0 if successful == len(nmx_folders) else 1


if __name__ == "__main__":
    exit(main()) 