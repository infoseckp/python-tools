import socket
import subprocess
import platform
import threading
from queue import Queue
import logging
import csv
from tabulate import tabulate
from network_scanning.service_detection import get_service_name
from network_scanning.vulnerability_check import check_vulnerabilities

N_THREADS = 100
queue = Queue()
open_ports = []

# Configure logging
logging.basicConfig(filename='scan_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def ping_sweep(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]

    try:
        output = subprocess.check_output(command)
        if "unreachable" in output.decode('utf-8'):
            return False
        return True
    except subprocess.CalledProcessError:
        return False

def banner_grab(ip, port, timeout):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        return banner
    except socket.error:
        return None

def port_scan(ip, port, timeout, verbose):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    if result == 0:
        banner = banner_grab(ip, port, timeout)
        service = get_service_name(port)
        open_ports.append((port, service, banner))
        logging.info(f"Port {port} is open. Service: {service}. Banner: {banner}")
        if verbose:
            print(f"Port {port} is open. Service: {service}. Banner: {banner}")
    sock.close()

def threader(ip, timeout, verbose):
    while True:
        worker = queue.get()
        port_scan(ip, worker, timeout, verbose)
        queue.task_done()

def scan(ip, timeout=1, verbose=True):
    print(f"Scanning {ip}...")

    if ping_sweep(ip):
        print(f"{ip} is up")
        logging.info(f"{ip} is up")
    else:
        print(f"{ip} is down")
        logging.info(f"{ip} is down")
        return

    ports = range(1, 1200)

    for _ in range(N_THREADS):
        thread = threading.Thread(target=threader, args=(ip, timeout, verbose))
        thread.daemon = True
        thread.start()

    for port in ports:
        queue.put(port)

    queue.join()

    if open_ports:
        with open('scan_results.csv', 'w', newline='') as csvfile:
            fieldnames = ['Port', 'Service', 'Banner']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for port, service, banner in open_ports:
                writer.writerow({'Port': port, 'Service': service, 'Banner': banner})

        # Display results in a table format
        table_data = []
        for port, service, banner in open_ports:
            vulnerabilities = check_vulnerabilities(service)
            table_data.append([port, service, banner, vulnerabilities])

        headers = ["Port", "Service", "Banner", "Vuln"]
        print(tabulate(table_data, headers, tablefmt="grid"))
    else:
        print(f"It seems all ports are closed. {ip}")



