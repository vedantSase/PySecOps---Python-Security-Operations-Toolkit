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

    def run_scan(self, target, arguments):
        target = self.format_target(target)
        print(f"{Fore.BLUE}[*] Initializing Scan on {target} with args: {arguments}...")
        
        # -T4 for speed, --open to show only responsive ports
        self.nm.scan(hosts=target, arguments=arguments + " -T4")
        
        table_data = []
        for host in self.nm.all_hosts():
            status = self.nm[host].state()
            if 'tcp' in self.nm[host]:
                for port, info in self.nm[host]['tcp'].items():
                    table_data.append({
                        "Host": host,
                        "Port": port,
                        "State": self.get_color_state(info['state']),
                        "Service": info['name'],
                        "Product": info.get('product', 'N/A'),
                        "Version": info.get('version', 'N/A')
                    })
            else:
                # For host-only scans
                table_data.append({"Host": host, "Status": status, "Port": "N/A", "State": "N/A", "Service": "N/A"})

        print("\n" + tabulate(table_data, headers="keys", tablefmt="fancy_grid"))
        if table_data:
            self.export_report(table_data, target)

    def host_scan_menu(self):
        print(f"\n{Fore.MAGENTA}--- Host Discovery ---")
        print("1. Ping Sweep (-sn -PE)")
        print("2. TCP SYN Ping (-sn -PS)")
        print("3. ARP Discovery (-sn -PR)")
        print("4. TCP ACK Ping (-sn -PA)")
        choice = input("Select Host Scan type: ")
        target = input("Enter Target (IP or 3-octets): ")
        
        args = {"1": "-sn -PE", "2": "-sn -PS", "3": "-sn -PR", "4": "-sn -PA"}.get(choice, "-sn")
        self.run_scan(target, args)

    def port_scan_menu(self):
        print(f"\n{Fore.MAGENTA}--- Port & Advanced Discovery ---")
        options = {
            "1": ("TCP Connect", "-sT"),
            "2": ("TCP Stealth (SYN)", "-sS"),
            "3": ("FIN Scan", "-sF"),
            "4": ("Xmas Scan", "-sX"),
            "5": ("Null Scan", "-sN"),
            "6": ("UDP Scan", "-sU"),
            "7": ("ACK Scan", "-sA"),
            "8": ("Version Detection", "-sV"),
            "9": ("OS Discovery", "-O"),
            "10": ("Aggressive", "-A"),
            "11": ("Zombie Scan", "-sI")
        }
        for k, v in options.items(): print(f"{k}. {v[0]}")
        
        choice = input("Select Scan type: ")
        if choice == "11":
            zombie = input("Enter Zombie Host IP: ")
            target = input("Enter Target IP: ")
            args = f"-sI {zombie}"
        else:
            target = input("Enter Target: ")
            args = options.get(choice, ("Standard", "-sV"))[1]
            
        self.run_scan(target, args)

    def main(self):
        while True:
            print(f"\n{Fore.CYAN}==============================")
            print(f"{Fore.WHITE}   NETWORK SCANNER v2.0")
            print(f"{Fore.CYAN}==============================")
            print("1. Host Scan")
            print("2. Port Scan")
            print("3. Full Scan (Deep)")
            print("4. Exit")
            
            m_choice = input("\nChoice > ")
            if m_choice == '1': self.host_scan_menu()
            elif m_choice == '2': self.port_scan_menu()
            elif m_choice == '3':
                target = input("Enter Target: ")
                # Full scan: All ports, OS detection, Scripts, and Versions
                self.run_scan(target, "-p- -A -sV -O")
            elif m_choice == '4': break

# if __name__ == "__main__":
scanner = AdvancedScanner()
scanner.main()
