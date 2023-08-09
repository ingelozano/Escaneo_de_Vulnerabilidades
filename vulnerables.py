import nmap

def scan_vulnerabilities(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-sV -Pn')

    print("Scanning:", target_ip)
    print("State:", nm[target_ip].state())
    
    for port in nm[target_ip]['tcp']:
        service = nm[target_ip]['tcp'][port]
        print(f"Port: {port} - Service: {service['name']} - Version: {service['version']}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    scan_vulnerabilities(target_ip)
