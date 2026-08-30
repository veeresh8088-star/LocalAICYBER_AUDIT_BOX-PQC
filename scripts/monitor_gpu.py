#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GPU Usage Monitor & Reporting Tool
==================================
Monitors NVIDIA GPU metrics (GPU %, VRAM Used, Power Draw, Temperature)
during an audit or workload execution, and generates a structured summary report.

Usage:
  1. Standalone background logging:
     python monitor_gpu.py --interval 1 --output gpu_metrics.csv --report gpu_report.md

  2. Wrap around a command (e.g. running an audit or container test):
     python monitor_gpu.py --cmd "python -m pytest tests/" --report test_gpu_report.md
"""

import os
import sys
import time
import argparse
import subprocess
import csv
from datetime import datetime

def query_nvidia_smi():
    """Queries nvidia-smi for current GPU stats across all available GPUs."""
    cmd = [
        "nvidia-smi",
        "--query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,memory.total,power.draw,temperature.gpu",
        "--format=csv,noheader,nounits"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
        gpu_data = []
        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 8:
                idx, name, gpu_util, mem_util, mem_used, mem_total, power, temp = parts[:8]
                gpu_data.append({
                    "index": int(idx),
                    "name": name,
                    "gpu_util_pct": float(gpu_util) if gpu_util != "[N/A]" else 0.0,
                    "mem_util_pct": float(mem_util) if mem_util != "[N/A]" else 0.0,
                    "mem_used_mb": float(mem_used) if mem_used != "[N/A]" else 0.0,
                    "mem_total_mb": float(mem_total) if mem_total != "[N/A]" else 0.0,
                    "power_w": float(power) if power != "[N/A]" else 0.0,
                    "temp_c": float(temp) if temp != "[N/A]" else 0.0,
                })
        return gpu_data
    except Exception as e:
        return None

def record_gpu_metrics(interval=1.0, duration=None, output_csv="gpu_metrics.csv", run_cmd=None):
    """Monitors GPU metrics continuously and returns metric records."""
    print("==========================================================")
    print("        NVIDIA GPU USAGE MONITORING STARTED               ")
    print("==========================================================")
    print(f"Interval: {interval}s | CSV Output: {output_csv}")
    
    initial_check = query_nvidia_smi()
    if initial_check is None:
        print("[ERROR] 'nvidia-smi' command failed or is not installed on this server.")
        print("Please ensure NVIDIA drivers and nvidia-smi are available in PATH.")
        sys.exit(1)
        
    print(f"Detected {len(initial_check)} GPU(s):")
    for g in initial_check:
        print(f"  - GPU {g['index']}: {g['name']} ({g['mem_total_mb']:.0f} MB VRAM)")
    print("----------------------------------------------------------\n")

    records = []
    start_time = time.time()
    
    csv_file = open(output_csv, "w", newline="", encoding="utf-8")
    writer = csv.writer(csv_file)
    writer.writerow(["Timestamp", "GPU_Index", "GPU_Name", "GPU_Util_Pct", "Mem_Util_Pct", "Mem_Used_MB", "Mem_Total_MB", "Power_W", "Temp_C"])
    csv_file.flush()

    proc = None
    if run_cmd:
        print(f"[LAUNCH] Running command: {run_cmd}\n")
        proc = subprocess.Popen(run_cmd, shell=True)

    try:
        while True:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            gpus = query_nvidia_smi()
            
            if gpus:
                for g in gpus:
                    rec = {
                        "timestamp": now_str,
                        "gpu_index": g["index"],
                        "gpu_name": g["name"],
                        "gpu_util_pct": g["gpu_util_pct"],
                        "mem_util_pct": g["mem_util_pct"],
                        "mem_used_mb": g["mem_used_mb"],
                        "mem_total_mb": g["mem_total_mb"],
                        "power_w": g["power_w"],
                        "temp_c": g["temp_c"]
                    }
                    records.append(rec)
                    writer.writerow([
                        rec["timestamp"], rec["gpu_index"], rec["gpu_name"],
                        rec["gpu_util_pct"], rec["mem_util_pct"], rec["mem_used_mb"],
                        rec["mem_total_mb"], rec["power_w"], rec["temp_c"]
                    ])
                    csv_file.flush()

            if proc is not None and proc.poll() is not None:
                print(f"\n[PROCESS FINISHED] Wrapped command exited with code {proc.returncode}")
                break

            elapsed = time.time() - start_time
            if duration and elapsed >= duration:
                print(f"\n[TIME LIMIT REACHED] Duration limit {duration}s reached.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Monitoring stopped by user.")
    finally:
        csv_file.close()

    return records, time.time() - start_time

def generate_report(records, total_duration, report_md="gpu_usage_report.md"):
    """Generates a structured Markdown summary report from collected GPU metrics."""
    if not records:
        print("[WARNING] No GPU metrics were collected to generate report.")
        return

    gpus_metrics = {}
    for r in records:
        idx = r["gpu_index"]
        if idx not in gpus_metrics:
            gpus_metrics[idx] = {
                "name": r["gpu_name"],
                "gpu_util": [],
                "mem_used": [],
                "mem_total": r["mem_total_mb"],
                "power": [],
                "temp": []
            }
        gpus_metrics[idx]["gpu_util"].append(r["gpu_util_pct"])
        gpus_metrics[idx]["mem_used"].append(r["mem_used_mb"])
        gpus_metrics[idx]["power"].append(r["power_w"])
        gpus_metrics[idx]["temp"].append(r["temp_c"])

    report_lines = []
    report_lines.append("# NVIDIA GPU Performance & Resource Usage Report")
    report_lines.append(f"**Report Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"**Total Sample Duration**: {total_duration:.1f} seconds ({total_duration/60.0:.2f} minutes)")
    report_lines.append(f"**Total Metric Samples**: {len(records)}\n")

    report_lines.append("## Executive Summary\n")
    report_lines.append("| GPU Index | GPU Model | Peak VRAM Used | Max VRAM Available | Avg GPU Util % | Max GPU Util % | Max Power (W) | Max Temp (°C) |")
    report_lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

    for idx, data in sorted(gpus_metrics.items()):
        name = data["name"]
        peak_vram_mb = max(data["mem_used"]) if data["mem_used"] else 0
        total_vram_mb = data["mem_total"]
        avg_gpu_util = sum(data["gpu_util"]) / len(data["gpu_util"]) if data["gpu_util"] else 0
        max_gpu_util = max(data["gpu_util"]) if data["gpu_util"] else 0
        max_power = max(data["power"]) if data["power"] else 0
        max_temp = max(data["temp"]) if data["temp"] else 0

        peak_vram_gb = peak_vram_mb / 1024.0
        total_vram_gb = total_vram_mb / 1024.0

        report_lines.append(
            f"| GPU {idx} | {name} | **{peak_vram_gb:.2f} GB** ({peak_vram_mb:.0f} MB) | {total_vram_gb:.2f} GB | "
            f"{avg_gpu_util:.1f}% | **{max_gpu_util:.1f}%** | {max_power:.1f} W | {max_temp:.1f} °C |"
        )

    report_lines.append("\n## Detailed Per-GPU Breakdown\n")

    for idx, data in sorted(gpus_metrics.items()):
        name = data["name"]
        avg_gpu = sum(data["gpu_util"]) / len(data["gpu_util"]) if data["gpu_util"] else 0
        max_gpu = max(data["gpu_util"]) if data["gpu_util"] else 0
        min_gpu = min(data["gpu_util"]) if data["gpu_util"] else 0
        
        avg_mem = sum(data["mem_used"]) / len(data["mem_used"]) if data["mem_used"] else 0
        max_mem = max(data["mem_used"]) if data["mem_used"] else 0
        total_mem = data["mem_total"]

        avg_pow = sum(data["power"]) / len(data["power"]) if data["power"] else 0
        max_pow = max(data["power"]) if data["power"] else 0

        report_lines.append(f"### GPU {idx}: {name}")
        report_lines.append(f"- **VRAM Footprint**: Peak {max_mem/1024.0:.2f} GB / {total_mem/1024.0:.2f} GB ({max_mem/total_mem*100.0:.1f}% of total)")
        report_lines.append(f"- **Average VRAM Allocation**: {avg_mem/1024.0:.2f} GB ({avg_mem:.0f} MB)")
        report_lines.append(f"- **GPU Core Utilization**: Avg {avg_gpu:.1f}% | Min {min_gpu:.1f}% | Max {max_gpu:.1f}%")
        report_lines.append(f"- **Power Draw**: Avg {avg_pow:.1f} W | Max {max_pow:.1f} W")
        report_lines.append(f"- **Peak Temperature**: {max(data['temp']):.1f} °C\n")

    report_content = "\n".join(report_lines)

    with open(report_md, "w", encoding="utf-8") as f:
        f.write(report_content)

    print("\n" + "=" * 60)
    print(f"[PASS] GPU SUMMARY REPORT GENERATED: {report_md}")
    print("=" * 60)
    print(report_content)

def main():
    parser = argparse.ArgumentParser(description="Capture GPU usage during workload execution and generate report.")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--duration", type=float, default=None, help="Sampling duration in seconds (optional)")
    parser.add_argument("--output", type=str, default="gpu_metrics.csv", help="Path to save raw CSV metrics")
    parser.add_argument("--report", type=str, default="gpu_usage_report.md", help="Path to save Markdown report")
    parser.add_argument("--cmd", type=str, default=None, help="Command to run while profiling GPU (e.g., 'python app.py')")

    args = parser.parse_args()

    records, total_duration = record_gpu_metrics(
        interval=args.interval,
        duration=args.duration,
        output_csv=args.output,
        run_cmd=args.cmd
    )

    generate_report(records, total_duration, report_md=args.report)

if __name__ == "__main__":
    main()
