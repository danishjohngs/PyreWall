"""
PyreWall — Personal Firewall Application
Entry point: choose CLI or Web Dashboard mode.

Usage:
    python run.py           → Interactive CLI
    python run.py --cli     → Interactive CLI
    python run.py --web     → Web Dashboard (http://127.0.0.1:5000)
    python run.py --demo    → Quick demo (no root needed)
"""
import sys


def main():
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
    else:
        mode = "--cli"

    if mode == "--web" or mode == "--dashboard":
        from app.dashboard import run_dashboard
        run_dashboard()
    elif mode == "--demo":
        from app.firewall import FirewallEngine
        from app.simulator import run_simulation
        fw = FirewallEngine(local_ip="192.168.1.100")
        fw.load_preset_basic()
        run_simulation(fw)
    else:
        from app.cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    main()
