import argparse
import subprocess
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich import box
from mantis_exploit import MantisExploit

console = Console()

class MantisMaster:
    def __init__(self, args):
        self.args = args
        self.all_vulns = []  # Kumpulin semua vuln dari semua target

    def run_scanner_on_target(self, target):
        """Jalankan scanner Go pada satu target, return open_ports dan banners"""
        open_ports = []
        banners = {}
        cmd = ['./scanner', '-t', target.strip(), '-w', str(self.args.workers)]
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
            for line in process.stdout:
                if "PORT" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        port = parts[2].replace(':', '')
                        banner = " ".join(parts[3:])
                        open_ports.append(int(port))
                        banners[int(port)] = banner
            process.wait(timeout=60)
        except Exception as e:
            console.print(f"[red]Scanner error pada {target}: {e}[/red]")
        return target, open_ports, banners

    def run_nuclei(self, targets_list, exploit_mode=False):
        """Jalankan Nuclei pada list target (bisa IP atau URL)"""
        if not targets_list:
            return []

        # Buat temporary file untuk input Nuclei
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
            for t in targets_list:
                tmp.write(t + '\n')
            tmp_path = tmp.name

        try:
            cmd = [
                "nuclei", "-l", tmp_path,
                "-severity", "critical,high,medium",
                "-json-export",  # Output JSON per finding
                "-silent"        # Biar tidak spam console
            ]
            if exploit_mode:
                cmd += ["-et", "intrusive"]  # Hanya jika user minta auto-exploit

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            os.unlink(tmp_path)  # Cleanup

            findings = []
            if result.stdout.strip():
                for line in result.stdout.strip().splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.append(data)
                        except json.JSONDecodeError:
                            continue
            return findings
        except subprocess.TimeoutExpired:
            console.print("[yellow]Nuclei timeout, melanjutkan...[/yellow]")
            return []
        except Exception as e:
            console.print(f"[red]Nuclei error: {e}[/red]")
            return []

    def process_single_target(self, target):
        target = target.strip()
        console.print(f"\n[bold cyan]Scanning → {target}[/bold cyan]")

        # Table live untuk port scan
        scan_table = Table(title=f"Open Ports - {target}", box=box.ROUNDED)
        scan_table.add_column("Port", style="cyan")
        scan_table.add_column("Proto", justify="center")
        scan_table.add_column("Status")
        scan_table.add_column("Service/Banner", style="dim")

        with Live(scan_table, refresh_per_second=4, console=console):
            target_ip, open_ports, banners = self.run_scanner_on_target(target)
            for port in open_ports:
                banner = banners.get(port, "No banner")
                scan_table.add_row(str(port), "TCP", "[green]OPEN[/green]", banner)

        vulns_this_target = []

        # Jalankan exploit misconfig (mantis_exploit.py)
        if self.args.exploit and open_ports:
            engine = MantisExploit(target_ip, open_ports)
            vulns = engine.start()
            for v in vulns:
                vulns_this_target.append({
                    "target": target,
                    "type": "Misconfig",
                    "name": v['type'],
                    "url": v.get('url', ''),
                    "severity": v.get('severity', 'HIGH'),
                    "details": v.get('details', '')
                })

        # Jalankan Nuclei jika diminta
        if self.args.nuclei and open_ports:
            # Buat list URL untuk Nuclei
            nuclei_targets = []
            web_ports = [p for p in open_ports if p in [80, 443, 8080, 8000, 3000, 5000, 8443]]
            for port in web_ports:
                schema = "https" if port in [443, 8443] else "http"
                nuclei_targets.append(f"{schema}://{target}:{port}")

            if nuclei_targets:
                console.print(f"[bold yellow]Running Nuclei on {target} ({len(nuclei_targets)} URLs)...[/bold yellow]")
                nuclei_findings = self.run_nuclei(nuclei_targets, exploit_mode=self.args.auto_exploit)

                for finding in nuclei_findings:
                    vulns_this_target.append({
                        "target": target,
                        "type": "Nuclei",
                        "name": finding.get("template-id", "Unknown"),
                        "url": finding.get("matched-at", ''),
                        "severity": finding.get("info", {}).get("severity", "info").upper(),
                        "details": finding.get("info", {}).get("name", ''),
                        "extracted": finding.get("extracted-results", [])
                    })

        return vulns_this_target

    def start(self):
        console.print("[bold green]MANTIS-TOOLS v2.0 - Hybrid Offensive Framework[/bold green]", justify="center")

        # Ambil list target
        if self.args.file:
            with open(self.args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            targets = [self.args.target]

        all_results = []

        # Proses paralel jika banyak target
        if len(targets) > 1:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.process_single_target, t): t for t in targets}
                for future in as_completed(futures):
                    all_results.extend(future.result())
        else:
            all_results = self.process_single_target(targets[0])

        # Gabungkan semua vuln
        self.all_vulns.extend(all_results)

        # Tampilkan ringkasan vulnerabilities
        if self.all_vulns:
            console.print("\n[bold red]=== VULNERABILITIES SUMMARY ===[/bold red]")
            vuln_table = Table(box=box.DOUBLE_EDGE)
            vuln_table.add_column("Target", style="cyan")
            vuln_table.add_column("Type", style="magenta")
            vuln_table.add_column("Severity", justify="center")
            vuln_table.add_column("Finding")
            vuln_table.add_column("URL/Details", style="dim")

            for v in self.all_vulns:
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "bright_red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                    "INFO": "blue"
                }.get(v["severity"], "white")

                vuln_table.add_row(
                    v["target"],
                    v["type"],
                    f"[{severity_color}]{v['severity']}[/{severity_color}]",
                    v["name"],
                    v["url"] or v["details"] or "-"
                )
            console.print(vuln_table)

            # Optional: simpan ke JSON
            if self.args.output:
                with open(self.args.output, 'w') as f:
                    json.dump(self.all_vulns, f, indent=2)
                console.print(f"\n[green]Report saved to {self.args.output}[/green]")
        else:
            console.print("\n[bold green]No vulnerabilities found.[/bold green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mantis-Tools v2.0 - Advanced Hybrid Scanner")
    parser.add_argument("-t", "--target", help="Single target IP/domain")
    parser.add_argument("-f", "--file", help="File containing list of targets (one per line)")
    parser.add_argument("-e", "--exploit", action="store_true", help="Enable misconfig exploitation (.env, .git, etc.)")
    parser.add_argument("-n", "--nuclei", action="store_true", help="Enable Nuclei vulnerability scanning")
    parser.add_argument("--auto-exploit", action="store_true", help="Enable intrusive Nuclei templates (DANGEROUS - use with permission only)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Scanner workers (default: 100)")
    parser.add_argument("-o", "--output", help="Save full report to JSON file")

    args = parser.parse_args()

    if not args.target and not args.file:
        console.print("[red]Error: Specify -t <target> or -f <file>[/red]")
        exit(1)

    MantisMaster(args).start()
