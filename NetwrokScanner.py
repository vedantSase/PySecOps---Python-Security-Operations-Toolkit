








# import nmap
# import os
# import sys
# from tabulate import tabulate
# from colorama import Fore, Style, init

# # Initialize Colorama for Windows/Linux compatibility
# init(autoreset=True)

# class AdvancedScanner:
#     def __init__(self):
#         try:
#             self.nm = nmap.PortScanner()
#         except nmap.PortScannerError:
#             print(f"{Fore.RED}Error: Nmap not found in system path.")
#             sys.exit(1)

#     def format_target(self, target):
#         """Converts 192.168.1 to 192.168.1.0/24 if 3 octets are provided."""
#         octets = target.split('.')
#         if len(octets) == 3:
#             full_target = f"{target}.0/24"
#             print(f"{Fore.CYAN}[!] Auto-corrected target to subnet: {full_target}")
#             return full_target
#         return target

#     def get_color_state(self, state):
#         """Returns color-coded state."""
#         if state == 'open': return f"{Fore.GREEN}open"
#         if state == 'closed': return f"{Fore.RED}closed"
#         if state == 'filtered': return f"{Fore.YELLOW}filtered"
#         return state

#     def export_report(self, data, target):
#         save = input(f"\n{Fore.YELLOW}Export results to .txt? (y/n): ").lower()
#         if save == 'y':
#             # Clean target name for filename
#             clean_ip = target.replace('/', '_')
#             filename = f"report_{clean_ip}.txt"
            
#             # If file exists, create a sequence (e.g., _1, _2)
#             counter = 1
#             while os.path.exists(filename):
#                 filename = f"report_{clean_ip}_{counter}.txt"
#                 counter += 1
                
#             with open(filename, "w") as f:
#                 f.write(tabulate(data, headers="keys", tablefmt="grid"))
#             print(f"{Fore.GREEN}[+] Report saved to {filename}")

#     def run_scan(self, target, arguments):
#         target = self.format_target(target)
#         print(f"{Fore.BLUE}[*] Initializing Scan on {target} with args: {arguments}...")
        
#         # -T4 for speed, --open to show only responsive ports
#         self.nm.scan(hosts=target, arguments=arguments + " -T4")
        
#         table_data = []
#         for host in self.nm.all_hosts():
#             status = self.nm[host].state()
#             if 'tcp' in self.nm[host]:
#                 for port, info in self.nm[host]['tcp'].items():
#                     table_data.append({
#                         "Host": host,
#                         "Port": port,
#                         "State": self.get_color_state(info['state']),
#                         "Service": info['name'],
#                         "Product": info.get('product', 'N/A'),
#                         "Version": info.get('version', 'N/A')
#                     })
#             else:
#                 # For host-only scans
#                 table_data.append({"Host": host, "Status": status, "Port": "N/A", "State": "N/A", "Service": "N/A"})

#         print("\n" + tabulate(table_data, headers="keys", tablefmt="fancy_grid"))
#         if table_data:
#             self.export_report(table_data, target)

#     def host_scan_menu(self):
#         print(f"\n{Fore.MAGENTA}--- Host Discovery ---")
#         print("1. Ping Sweep (-sn -PE)")
#         print("2. TCP SYN Ping (-sn -PS)")
#         print("3. ARP Discovery (-sn -PR)")
#         print("4. TCP ACK Ping (-sn -PA)")
#         choice = input("Select Host Scan type: ")
#         target = input("Enter Target (IP or 3-octets): ")
        
#         args = {"1": "-sn -PE", "2": "-sn -PS", "3": "-sn -PR", "4": "-sn -PA"}.get(choice, "-sn")
#         self.run_scan(target, args)

#     def port_scan_menu(self):
#         print(f"\n{Fore.MAGENTA}--- Port & Advanced Discovery ---")
#         options = {
#             "1": ("TCP Connect", "-sT"),
#             "2": ("TCP Stealth (SYN)", "-sS"),
#             "3": ("FIN Scan", "-sF"),
#             "4": ("Xmas Scan", "-sX"),
#             "5": ("Null Scan", "-sN"),
#             "6": ("UDP Scan", "-sU"),
#             "7": ("ACK Scan", "-sA"),
#             "8": ("Version Detection", "-sV"),
#             "9": ("OS Discovery", "-O"),
#             "10": ("Aggressive", "-A"),
#             "11": ("Zombie Scan", "-sI")
#         }
#         for k, v in options.items(): print(f"{k}. {v[0]}")
        
#         choice = input("Select Scan type: ")
#         if choice == "11":
#             zombie = input("Enter Zombie Host IP: ")
#             target = input("Enter Target IP: ")
#             args = f"-sI {zombie}"
#         else:
#             target = input("Enter Target: ")
#             args = options.get(choice, ("Standard", "-sV"))[1]
            
#         self.run_scan(target, args)

#     def main(self):
#         while True:
#             print(f"\n{Fore.CYAN}==============================")
#             print(f"{Fore.WHITE}   NETWORK SCANNER v2.0")
#             print(f"{Fore.CYAN}==============================")
#             print("1. Host Scan")
#             print("2. Port Scan")
#             print("3. Full Scan (Deep)")
#             print("4. Exit")
            
#             m_choice = input("\nChoice > ")
#             if m_choice == '1': self.host_scan_menu()
#             elif m_choice == '2': self.port_scan_menu()
#             elif m_choice == '3':
#                 target = input("Enter Target: ")
#                 # Full scan: All ports, OS detection, Scripts, and Versions
#                 self.run_scan(target, "-p- -A -sV -O")
#             elif m_choice == '4': 
#                 break
#                 return "back"

# # if __name__ == "__main__":
# scanner = AdvancedScanner()
# scanner.main()














# import nmap
# import os
# import sys
# import time
# import threading
# import itertools
# from datetime import datetime
# from tabulate import tabulate
# from colorama import Fore, Style, init

# # Initialize Colorama
# init(autoreset=True)

# class ScannerEngine:
#     def __init__(self):
#         try:
#             self.nm = nmap.PortScanner()
#         except nmap.PortScannerError:
#             print(f"{Fore.RED}Error: Nmap not found. Please install Nmap and add it to your PATH.")
#             sys.exit(1)

#     def format_target(self, target):
#         """Converts 3 octets (192.168.1) to 192.168.1.0/24."""
#         octets = target.split('.')
#         if len(octets) == 3:
#             return f"{target}.0/24"
#         return target

#     def get_color_state(self, state):
#         if state == 'open': return f"{Fore.GREEN}open"
#         if state == 'closed': return f"{Fore.RED}closed"
#         return f"{Fore.YELLOW}{state}"

#     def animate(self, stop_event):
#         """Displays a simple loading animation."""
#         for c in itertools.cycle(['|', '/', '-', '\\']):
#             if stop_event.is_set():
#                 break
#             sys.stdout.write(f'\r{Fore.CYAN}[*] Scanning in progress... {c} ')
#             sys.stdout.flush()
#             time.sleep(0.1)
#         sys.stdout.write('\r' + ' ' * 30 + '\r')

#     def execute_scan(self, target, args):
#         target = self.format_target(target)
#         print(f"{Fore.BLUE}[!] Target: {target}")
        
#         # Start Animation Thread
#         stop_animation = threading.Event()
#         animation_thread = threading.Thread(target=self.animate, args=(stop_animation,))
#         animation_thread.start()

#         try:
#             self.nm.scan(hosts=target, arguments=args + " -T4")
#         finally:
#             stop_animation.set()
#             animation_thread.join()

#         scan_results = []
#         for host in self.nm.all_hosts():
#             host_name = self.nm[host].hostname()
#             state = self.nm[host].state()
            
#             # If it's a port-based scan
#             if 'tcp' in self.nm[host]:
#                 for port, info in self.nm[host]['tcp'].items():
#                     scan_results.append({
#                         "Host": host,
#                         "Hostname": host_name if host_name else "N/A",
#                         "Port": port,
#                         "State": self.get_color_state(info['state']),
#                         "Service": info['name'],
#                         "Version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "N/A"
#                     })
#             else:
#                 # If it's a host-only discovery scan
#                 scan_results.append({
#                     "Host": host,
#                     "Hostname": host_name if host_name else "N/A",
#                     "Status": f"{Fore.GREEN}{state}" if state == 'up' else f"{Fore.RED}{state}",
#                     "Note": "Host discovery only"
#                 })
        
#         return scan_results, target

#     def export_data(self, data, target):
#         choice = input(f"\n{Fore.YELLOW}Export result to .txt? (y/n): ").lower()
#         if choice == 'y':
#             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#             clean_ip = target.replace('/', '_')
#             filename = f"Scan_{clean_ip}_{timestamp}.txt"
            
#             # Additional check if file exists (redundant with timestamp but safe)
#             if os.path.exists(filename):
#                 filename = f"Scan_{clean_ip}_{timestamp}_new.txt"

#             with open(filename, "w") as f:
#                 f.write(f"NETWORK SCAN REPORT - {target}\n")
#                 f.write(f"Generated on: {datetime.now()}\n")
#                 f.write("="*50 + "\n")
#                 f.write(tabulate(data, headers="keys", tablefmt="grid"))
            
#             print(f"{Fore.GREEN}[+] Report saved successfully: {filename}")

# # --- Menu Functions (Outside Class) ---

# def host_scan_menu(scanner):
#     while True:
#         print(f"\n{Fore.MAGENTA}--- HOST DISCOVERY ---")
#         print("1. Ping Sweep (-sn -PE)")
#         print("2. TCP SYN Ping (-sn -PS)")
#         print("3. ARP Discovery (-sn -PR)")
#         print("4. TCP ACK Ping (-sn -PA)")
#         print("0. Back")
        
#         choice = input("\nSelect Host Scan: ")
#         if choice == '0': return "back"
        
#         args = {"1": "-sn -PE", "2": "-sn -PS", "3": "-sn -PR", "4": "-sn -PA"}.get(choice)
#         if args:
#             target = input("Enter Target (e.g. 192.168.1 or 192.168.1.1): ")
#             results, final_target = scanner.execute_scan(target, args)
#             print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
#             if results: scanner.export_data(results, final_target)
#         else:
#             print(f"{Fore.RED}Invalid choice!")

# def port_scan_menu(scanner):
#     while True:
#         print(f"\n{Fore.MAGENTA}--- PORT DISCOVERY ---")
#         options = {
#             "1": ("TCP Connect", "-sT"), "2": ("TCP Stealth", "-sS"),
#             "3": ("FIN Scan", "-sF"), "4": ("Xmas Scan", "-sX"),
#             "5": ("Null Scan", "-sN"), "6": ("UDP Scan", "-sU"),
#             "7": ("ACK Scan", "-sA"), "8": ("Version Scan", "-sV"),
#             "9": ("OS Discovery", "-O"), "10": ("Aggressive", "-A"),
#             "11": ("Zombie Scan", "-sI")
#         }
#         for k, v in options.items(): print(f"{k}. {v[0]}")
#         print("0. Back")

#         choice = input("\nSelect Port Scan: ")
#         if choice == '0': break

#         if choice in options:
#             target = input("Enter Target IP: ")
#             arg = options[choice][1]
#             if choice == "11":
#                 zombie = input("Enter Zombie Host: ")
#                 arg = f"-sI {zombie}"
            
#             results, final_target = scanner.execute_scan(target, arg)
#             print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
#             if results: scanner.export_data(results, final_target)
#         else:
#             print(f"{Fore.RED}Invalid choice!")

# def main():
#     scanner = ScannerEngine()
#     while True:
#         print(f"\n{Fore.CYAN}{'='*35}")
#         print(f"{Fore.WHITE}      ULTIMATE NETWORK SCANNER")
#         print(f"{Fore.CYAN}{'='*35}")
#         print("1. Host Scan")
#         print("2. Port Scan")
#         print("3. Full Scan (Deep Inspection)")
#         print("4. Exit")

#         m_choice = input("\nMain Menu Selection > ")

#         if m_choice == '1':
#             host_scan_menu(scanner)
#         elif m_choice == '2':
#             port_scan_menu(scanner)
#         elif m_choice == '3':
#             target = input("Enter Target (IP or Subnet): ")
#             # Full scan: All ports (-p-), Aggressive (-A), and Service info
#             results, final_target = scanner.execute_scan(target, "-p- -A -sV")
#             print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
#             if results: scanner.export_data(results, final_target)
#         elif m_choice == '4':
#             print(f"{Fore.YELLOW}Exiting...")
#             return "back"
#         else:
#             print(f"{Fore.RED}Invalid Input!")

# if __name__ == "__main__":
#     main()






import nmap
import os
import sys
import time
import threading
import itertools
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

class ScannerEngine:
    def __init__(self):
        try:
            # Initializing Nmap with -V to check if it's installed
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print(f"{Fore.RED}Error: Nmap not found. Please install Nmap (https://nmap.org) and add it to your PATH.")
            sys.exit(1)

    def format_target(self, target):
        """Converts 3 octets (192.168.1) to 192.168.1.0/24."""
        octets = target.split('.')
        if len(octets) == 3:
            return f"{target}.0/24"
        return target

    def get_color_state(self, state):
        if state == 'open': return f"{Fore.GREEN}open"
        if state == 'closed': return f"{Fore.RED}closed"
        if state == 'filtered': return f"{Fore.YELLOW}filtered"
        return f"{Fore.CYAN}{state}"

    def animate(self, stop_event):
        """Displays an informative loading animation."""
        chars = itertools.cycle(['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'])
        for char in chars:
            if stop_event.is_set():
                break
            sys.stdout.write(f'\r{Fore.CYAN}[{char}] Scanning Engine Active... Please wait...')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * 50 + '\r')

    def execute_scan(self, target, args):
        target = self.format_target(target)
        print(f"\n{Fore.BLUE}[INFO] Initializing Detailed Scan...\n")
        print(f"{Fore.BLUE}[INFO] Target: {Fore.WHITE}{target}")
        print(f"{Fore.BLUE}[INFO] Parameters: {Fore.WHITE}{args}")
        
        stop_animation = threading.Event()
        animation_thread = threading.Thread(target=self.animate, args=(stop_animation,))
        animation_thread.start()

        start_time = datetime.now()
        try:
            # -T4 for speed, --stats-every for internal tracking
            self.nm.scan(hosts=target, arguments=f"{args} -T4")
        except Exception as e:
            print(f"{Fore.RED}\n[!] Scan Error: {e}\n")
        finally:
            stop_animation.set()
            animation_thread.join()
        
        end_time = datetime.now()
        duration = end_time - start_time

        scan_results = []
        for host in self.nm.all_hosts():
            h_obj = self.nm[host]
            
            # Extract basic host info
            hostname = h_obj.hostname() or "Unknown"
            mac = h_obj['addresses'].get('mac', 'N/A')
            vendor = h_obj['vendor'].get(mac, 'N/A')
            latency = h_obj.get('vendor', {}).get('latency', 'N/A') # May require root
            
            # Extract OS Info (if -O or -A was used)
            os_match = "N/A"
            if 'osmatch' in h_obj and h_obj['osmatch']:
                os_match = h_obj['osmatch'][0].get('name', 'N/A')

            # Detailed Port Data
            if 'tcp' in h_obj:
                for port, info in h_obj['tcp'].items():
                    scan_results.append({
                        "IP Address": host,
                        "Hostname": hostname,
                        "Port": port,
                        "State": self.get_color_state(info['state']),
                        "Service": info['name'],
                        "Version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "N/A",
                        "Reason": info.get('reason', 'N/A'),
                        "OS Guess": os_match,
                        "MAC / Vendor": f"{mac} ({vendor})" if mac != 'N/A' else "N/A"
                    })
            else:
                # Fallback for Host Discovery
                state = h_obj.state()
                scan_results.append({
                    "IP Address": host,
                    "Hostname": hostname,
                    "Port": "N/A",
                    "State": f"{Fore.GREEN}UP" if state == 'up' else f"{Fore.RED}DOWN",
                    "Service": "N/A",
                    "Version": "N/A",
                    "Reason": h_obj.get('status', {}).get('reason', 'N/A'),
                    "OS Guess": os_match,
                    "MAC / Vendor": f"{mac} ({vendor})" if mac != 'N/A' else "N/A"
                })
        
        print(f"{Fore.GREEN}\n[*] Scan completed in {duration.total_seconds():.2f} seconds.")
        return scan_results, target

    def export_data(self, data, target):
        choice = input(f"\n{Fore.YELLOW}Export these results to a .txt document? (y/n): ").lower()
        if choice == 'y':
            # Create filename using IP and precise timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_ip = target.replace('/', '_').replace('.', '-')
            filename = f"Scan_{clean_ip}_{timestamp}.txt"
            
            # Ensure uniqueness
            if os.path.exists(filename):
                filename = f"Scan_{clean_ip}_{timestamp}_v2.txt"

            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"NETWORK SCAN REPORT\n")
                f.write(f"Target Scope: {target}\n")
                f.write(f"Timestamp:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 80 + "\n")
                # Using grid for the text file to keep it readable
                f.write(tabulate(data, headers="keys", tablefmt="grid"))
                f.write(f"\n\n[EOF] Total Records: {len(data)}")
            
            print(f"{Fore.CYAN}[+] Detailed report generated: {Fore.WHITE}{os.path.abspath(filename)}")

# --- Menu Functions (Procedural Logic) ---

def host_scan_menu(scanner):
    while True:
        print(f"\n{Fore.MAGENTA}--- HOST DISCOVERY OPTIONS ---\n")
        print("1. Ping Sweep (-sn -PE) - Basic L3 Discovery")
        print("2. TCP SYN Ping (-sn -PS) - Firewall Bypass")
        print("3. ARP Discovery (-sn -PR) - Local Network")
        print("4. TCP ACK Ping (-sn -PA) - Stateless Discovery")
        print(f"{Fore.RED}0. Back to Main Menu")
        
        choice = input(f"\n{Fore.WHITE}Select Option: ")
        if choice == '0': break
        
        args = {"1": "-sn -PE", "2": "-sn -PS", "3": "-sn -PR", "4": "-sn -PA"}.get(choice)
        if args:
            target = input(f"{Fore.CYAN}Enter IP/Subnet (e.g. 192.168.1): ")
            results, final_target = scanner.execute_scan(target, args)
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
            else:
                print(f"{Fore.RED}[!] No live hosts detected with this method.")
        else:
            print(f"{Fore.RED}Invalid selection.")

def port_scan_menu(scanner):
    while True:
        print(f"\n{Fore.MAGENTA}--- PORT DISCOVERY & RECON ---\n")
        options = {
            "1": ("TCP Connect Scan", "-sT"),
            "2": ("TCP Stealth (SYN)", "-sS"),
            "3": ("FIN Scan (Inverse)", "-sF"),
            "4": ("Xmas Scan (Inverse)", "-sX"),
            "5": ("Null Scan (Inverse)", "-sN"),
            "6": ("UDP Scan", "-sU"),
            "7": ("ACK Scan (Firewall mapping)", "-sA"),
            "8": ("Service/Version Detection", "-sV"),
            "9": ("OS Discovery", "-O"),
            "10": ("Aggressive (All-in-one)", "-A"),
            "11": ("Zombie (Idle) Scan", "-sI")
        }
        for k, v in options.items():
            print(f"{k}. {v[0]} ({v[1]})")
        print(f"{Fore.RED}0. Back to Main Menu")

        choice = input(f"\n{Fore.WHITE}Select Option: ")
        if choice == '0': break

        if choice in options:
            target = input(f"{Fore.CYAN}Enter Target IP: ")
            arg = options[choice][1]
            if choice == "11":
                zombie = input("Enter Zombie (Idle) Host IP: ")
                target = input("Enter Target IP: ")
                arg = f"-sI {zombie}"
            
            results, final_target = scanner.execute_scan(target, arg)
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
        else:
            print(f"{Fore.RED}Invalid selection.")

def main():
    scanner = ScannerEngine()
    while True:
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════╗")
        print(f"{Fore.CYAN}║{Fore.WHITE}      NETWORK SCANNER              {Fore.CYAN}║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════╝")
        print(f"{Fore.YELLOW}           By PySecOps ")
        print(f"{Fore.CYAN}\n-------------------------------------\n")
        print("1. Host Scan  (Discover live devices)")
        print("2. Port Scan  (Detailed service discovery)")
        print("3. Full Scan  (Deep inspection - All ports)")
        print(f"{Fore.RED}4. Exit Application")

        m_choice = input(f"\n{Fore.WHITE}Select Scan Type : ")

        if m_choice == '1':
            host_scan_menu(scanner)
        elif m_choice == '2':
            port_scan_menu(scanner)
        elif m_choice == '3':
            target = input(f"{Fore.CYAN}Enter Target (e.g. 10.0.0.1 or 192.168.1): ")
            # Deep Scan: Full port range, Aggressive scripts, OS, and Versions
            results, final_target = scanner.execute_scan(target, "-p- -A -sV")
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
        elif m_choice == '4':
            print(f"{Fore.YELLOW}[!] Shutting down scanner...")
            return "back"
        else:
            print(f"{Fore.RED}[!] Input Error: Please choose 1-4.")

if __name__ == "__main__":
    main()
