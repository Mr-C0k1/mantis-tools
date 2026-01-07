# mantis_post_exp.py - POST EXPLOITATION & VULNERABILITY REPORT v2.0
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import json

console = Console()

def severity_emoji(severity: str) -> str:
    return {
        "CRITICAL": "💀",
        "HIGH":     "🟥",
        "MEDIUM":   "🟨",
        "LOW":      "🟩",
        "INFO":     "ℹ️"
    }.get(severity.upper(), "⚪")

def post_exploitation_report(all_vulns: list, output_file: str = None):
    if not all_vulns:
        console.print("\n[bold green]🎉 No vulnerabilities or exposures found! Target looks clean.[/bold green]")
        return

    console.print("\n[bold red]╔═══════════════════════════════════════════════════════════")
    console.print("[bold red]   MANTIS-TOOLS POST EXPLOITATION REPORT")
    console.print("[bold red]╚═══════════════════════════════════════════════════════════[/bold red]")

    # Group by target
    targets = {}
    for v in all_vulns:
        targets.setdefault(v["target"], []).append(v)

    critical_count = sum(1 for v in all_vulns if v["severity"] == "CRITICAL")

    if critical_count > 0:
        console.print(f"\n[bold red]⚠️  {critical_count} CRITICAL vulnerabilities detected! Immediate action required![/bold red]\n")

    for target, vulns in targets.items():
        table = Table(title=f"[bold cyan]Target: {target}[/bold cyan]", box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Severity", width=10)
        table.add_column("Type", width=15)
        table.add_column("Finding", width=40)
        table.add_column("Details / Loot", style="dim")

        for v in vulns:
            sev = v["severity"].upper()
            emoji = severity_emoji(sev)
            finding_name = v.get("name", v.get("type", "Unknown"))
            
            # Handle extracted secrets or data
            loot = ""
            if "semgrep_findings" in v and v["semgrep_findings"]:
                secrets = [f["extra"]["message"] for f in v["semgrep_findings"][:3]]
                loot = " | ".join(secrets)
                if len(v["semgrep_findings"]) > 3:
                    loot += f" (+{len(v['semgrep_findings'])-3} more)"
            elif "extracted" in v and v["extracted"]:
                loot = " | ".join(v["extracted"][:3])
            elif v.get("url"):
                loot = v["url"]

            table.add_row(
                f"{emoji} [{sev.lower()}]{sev}[/{sev.lower()}]",
                v.get("type", "Unknown"),
                finding_name,
                loot or "-"
            )

        console.print(table)

    # Summary statistik
    stats = Table.grid()
    stats.add_column(style="bold")
    stats.add_column()
    stats.add_row("Total Findings", str(len(all_vulns)))
    stats.add_row("Critical", str(sum(1 for v in all_vulns if v["severity"] == "CRITICAL")))
    stats.add_row("High", str(sum(1 for v in all_vulns if v["severity"] == "HIGH")))
    stats.add_row("From Nuclei", str(sum(1 for v in all_vulns if v["type"] == "Nuclei")))
    stats.add_row("Misconfig/Secrets", str(sum(1 for v in all_vulns if v["type"] == "Misconfig")))
    console.print(Panel(stats, title="[bold green]Summary[/bold green]", border_style="green"))

    # Simpan ke file jika diminta
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(all_vulns, f, indent=2)
        console.print(f"\n[green]Full detailed report saved → {output_file}[/green]")
