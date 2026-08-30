#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Resource Monitor (CPU Core % & RAM Logger)
==================================================
Monitors System-wide CPU Core Utilization %, Active Cores, RAM Used (GB),
and Swap Usage during parallel audit execution, producing an executive summary.

Usage:
  python scripts/system_resource_monitor.py --interval 1 --duration 60
  python scripts/system_resource_monitor.py --cmd "python scripts/simulate_real_ui_users.py --users 10"
"""

import os
import sys
import time
import csv
import argparse
import subprocess
from datetime import datetime

try:
    import psutil
except ImportError:
    print("[ERROR] 'psutil' package is required. Installing via pip...")
    subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True)
    import psutil

def monitor_system_resources(interval=1.0, duration=None, output_csv="system_resource_metrics.csv", run_cmd=None):
    print("=" * 70)
    print("        SYSTEM CPU CORE & RAM RESOURCE MONITORING STARTED       ")
    print("=" * 70)
    
    try:
        logical_cores = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        logical_cores = psutil.cpu_count(logical=True) or 1
    physical_cores = logical_cores
    total_ram_gb = psutil.virtual_memory().total / (1024.0 ** 3)

    print(f"Detected Hardware Specs:")
    print(f"  - Physical Cores: {physical_cores}")
    print(f"  - Logical Cores / Threads: {logical_cores}")
    print(f"  - Total System RAM: {total_ram_gb:.2f} GB")
    print(f"Sampling Interval: {interval}s | CSV Output: {output_csv}\n")

    proc = None
    if run_cmd:
        print(f"[LAUNCH] Executing workload command: {run_cmd}\n")
        proc = subprocess.Popen(run_cmd, shell=True)

    records = []
    start_time = time.time()

    f = open(output_csv, "w", newline="", encoding="utf-8")
    writer = csv.writer(f)
    writer.writerow([
        "Timestamp", "Overall_CPU_Pct", "Active_Cores_Used",
        "RAM_Used_GB", "RAM_Total_GB", "RAM_Util_Pct", "Available_RAM_GB"
    ])
    f.flush()

    try:
        while True:
            t_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cpu_pct = psutil.cpu_percent(interval=interval)
            active_cores = round((cpu_pct / 100.0) * logical_cores, 2)
            
            mem = psutil.virtual_memory()
            ram_used_gb = round(mem.used / (1024.0 ** 3), 2)
            ram_avail_gb = round(mem.available / (1024.0 ** 3), 2)
            ram_pct = mem.percent

            rec = {
                "timestamp": t_str,
                "cpu_pct": cpu_pct,
                "active_cores": active_cores,
                "ram_used_gb": ram_used_gb,
                "ram_total_gb": round(total_ram_gb, 2),
                "ram_pct": ram_pct,
                "ram_avail_gb": ram_avail_gb
            }
            records.append(rec)
            writer.writerow([
                t_str, cpu_pct, active_cores, ram_used_gb,
                round(total_ram_gb, 2), ram_pct, ram_avail_gb
            ])
            f.flush()

            if proc is not None and proc.poll() is not None:
                print(f"\n[PROCESS FINISHED] Command exited with code {proc.returncode}")
                break

            elapsed = time.time() - start_time
            if duration and elapsed >= duration:
                print(f"\n[DURATION REACHED] Stopped after {duration} seconds.")
                break

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Monitoring stopped by user.")
    finally:
        f.close()

    total_wall_time = time.time() - start_time
    return records, total_wall_time, logical_cores, total_ram_gb

def generate_summary(records, total_wall_time, logical_cores, total_ram_gb, report_md="system_resource_report.md"):
    if not records:
        print("[WARNING] No metrics collected to build report.")
        return

    avg_cpu = sum(r["cpu_pct"] for r in records) / len(records)
    max_cpu = max(r["cpu_pct"] for r in records)
    
    avg_cores = sum(r["active_cores"] for r in records) / len(records)
    max_cores = max(r["active_cores"] for r in records)

    avg_ram = sum(r["ram_used_gb"] for r in records) / len(records)
    max_ram = max(r["ram_used_gb"] for r in records)

    report_content = f"""# System CPU Core & Memory Resource Usage Report

**Report Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Monitoring Duration**: {total_wall_time:.1f} seconds ({total_wall_time/60.0:.2f} minutes)
**Hardware Environment**: {logical_cores} Logical CPU Cores | {total_ram_gb:.2f} GB RAM

## Executive Resource Summary

| Hardware Metric | Average Utilization | Peak / Maximum | Total Available |
| :--- | :--- | :--- | :--- |
| **CPU Utilization %** | **{avg_cpu:.1f}%** | **{max_cpu:.1f}%** | 100% |
| **Active CPU Cores Used** | **{avg_cores:.2f} Cores** | **{max_cores:.2f} Cores** | {logical_cores} Cores |
| **RAM Consumption** | **{avg_ram:.2f} GB** | **{max_ram:.2f} GB** | {total_ram_gb:.2f} GB |
| **RAM Utilization %** | **{(avg_ram/total_ram_gb)*100.0:.1f}%** | **{(max_ram/total_ram_gb)*100.0:.1f}%** | 100% |

## Detailed Observations
- **Average Active CPU Cores**: The workload utilized an average of **{avg_cores:.2f} CPU cores** out of {logical_cores} available cores.
- **Peak CPU Core Usage**: At maximum load, the system reached **{max_cores:.2f} CPU cores** ({max_cpu:.1f}% total capacity).
- **RAM Memory Footprint**: Average memory footprint was **{avg_ram:.2f} GB**, reaching a peak allocation of **{max_ram:.2f} GB**.
"""

    with open(report_md, "w", encoding="utf-8") as f:
        f.write(report_content)

    print("\n" + "=" * 70)
    print(f"[PASS] RESOURCE REPORT GENERATED: {report_md}")
    print("=" * 70)
    print(report_content)

def main():
    parser = argparse.ArgumentParser(description="Monitor CPU Core % and RAM footprint during audit execution.")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--duration", type=float, default=None, help="Sampling duration in seconds")
    parser.add_argument("--output", type=str, default="system_resource_metrics.csv", help="Output CSV path")
    parser.add_argument("--report", type=str, default="system_resource_report.md", help="Output Markdown report path")
    parser.add_argument("--cmd", type=str, default=None, help="Command to run while monitoring resources")

    args = parser.parse_args()

    records, total_wall_time, logical_cores, total_ram_gb = monitor_system_resources(
        interval=args.interval,
        duration=args.duration,
        output_csv=args.output,
        run_cmd=args.cmd
    )

    generate_summary(records, total_wall_time, logical_cores, total_ram_gb, report_md=args.report)

if __name__ == "__main__":
    main()
