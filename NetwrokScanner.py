import nmap
import os
import sys
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize Colorama for Windows/Linux compatibility
init(autoreset=True)

class AdvancedScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print(f"{Fore.RED}Error: Nmap not found in system path.")
            sys.exit(1)

    def format_target(self, target):
        """Converts 192.168.1 to 192.168.1.0/24 if 3 octets are provided."""
        octets = target.split('.')
        if len(octets) == 3:
            full_target = f"{target}.0/24"
            print(f"{Fore.CYAN}[!] Auto-corrected target to subnet: {full_target}")
            return full_target
        return target

    def get_color_state(self, state):
        """Returns color-coded state."""
        if state == 'open': return f"{Fore.GREEN}open"
        if state == 'closed': return f"{Fore.RED}closed"
        if state == 'filtered': return f"{Fore.YELLOW}filtered"
        return state

    def export_report(self, data, target):
        save = input(f"\n{Fore.YELLOW}Export results to .txt? (y/n): ").lower()
        if save == 'y':
            # Clean target name for filename
            clean_ip = target.replace('/', '_')
            filename = f"report_{clean_ip}.txt"
            
            # If file exists, create a sequence (e.g., _1, _2)
            counter = 1
            while os.path.exists(filename):
                filename = f"report_{clean_ip}_{counter}.txt"
                counter += 1
                
            with open(filename, "w") as f:
                f.write(tabulate(data, headers="keys", tablefmt="grid"))
            print(f"{Fore.GREEN}[+] Report saved to {filename}")
