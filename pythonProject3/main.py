from network_scanning import net_scan
from web_scanning import web_scan
from exploitation import exploit

def main():
    print("Welcome. Thank you for testing")
    print("1. Network Scanning")
    print("2. Web Vulnerability Scanning")
    print("3. Basic Exploitation")

    choice = input("Choose an option: ")

    if choice == '1':
        target_ip = input("Enter target IP or IP range: ")
        net_scan.scan(target_ip)
    elif choice == '2':
        url = input("Enter target URL: ")
        web_scan.scan(url)
    elif choice == '3':
        target_ip = input("Enter target IP: ")
        exploit.exploit(target_ip)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
