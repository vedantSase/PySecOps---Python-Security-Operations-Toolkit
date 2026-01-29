import time
import nmap

def scan_network(target):
    time.sleep(2)
    print(f"Starting network scan on {target}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-Ss') 

    for host in nm.all_hosts():
        print(f"Scanning host: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                print(f"Port {port}/{proto} is {state}")

if __name__ == "__main__":
    target = '192.168.31.0/24'
    scan_network(target)