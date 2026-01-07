import argparse
import subprocess
from rich.console import Console
from rich.table import Table
from rich.live import Live
from mantis_exploit import MantisExploit

console = Console()

class MantisMaster:
    def __init__(self, args):
        self.args = args
        self.open_ports = []

    def run_scan(self, live_table):
        cmd = ['./scanner', '-t', self.args.target, '-w', str(self.args.workers)]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            if "PORT" in line:
                parts = line.split()
                port = parts[2].replace(':', '')
                banner = " ".join(parts[3:])
                self.open_ports.append(int(port))
                live_table.add_row(port, "TCP", "[green]OPEN[/green]", banner)

    def start(self):
        console.print("[bold green]MANTIS-TOOLS v1.0[/bold green]", justify="center")
        scan_table = Table(title=f"Target: {self.args.target}", expand=True)
        scan_table.add_column("Port")
        scan_table.add_column("Proto")
        scan_table.add_column("Status")
        scan_table.add_column("Banner")

        with Live(scan_table, refresh_per_second=4):
            self.run_scan(scan_table)

        if self.args.exploit:
            engine = MantisExploit(self.args.target, self.open_ports)
            vulns = engine.start()
            if vulns:
                console.print("\n[bold red]VULNERABILITIES FOUND:[/bold red]")
                for v in vulns:
                    console.print(f"  [!] {v['type']}: {v['url']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-e", "--exploit", action="store_true")
    parser.add_argument("-w", "--workers", type=int, default=100)
    MantisMaster(parser.parse_args()).start()
