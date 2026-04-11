import nmap
import socket
import platform
import subprocess
import re
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ─── RISK LEVELS ────────────────────────────────────────────────────────────
HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"
INFO   = "INFO"

RISK_COLOURS = {
    HIGH:   Fore.RED,
    MEDIUM: Fore.YELLOW,
    LOW:    Fore.GREEN,
    INFO:   Fore.CYAN,
}

# ─── KNOWN DANGEROUS PORTS ──────────────────────────────────────────────────
DANGEROUS_PORTS = {
    21:   ("FTP",              HIGH,   "Unencrypted file transfer. Credentials sent in plaintext."),
    22:   ("SSH",              MEDIUM, "Remote access. Acceptable if needed — ensure key-based auth only."),
    23:   ("Telnet",           HIGH,   "Completely unencrypted remote access. Should never be open."),
    25:   ("SMTP",             MEDIUM, "Mail server. Exposure may allow spam relay."),
    53:   ("DNS",              MEDIUM, "DNS server exposed. Verify this is intentional."),
    80:   ("HTTP",             LOW,    "Unencrypted web server. Consider HTTPS only."),
    110:  ("POP3",             MEDIUM, "Unencrypted email retrieval."),
    135:  ("RPC",              HIGH,   "Windows RPC. Frequent target for exploitation."),
    139:  ("NetBIOS",          HIGH,   "Legacy Windows file sharing. Major attack surface."),
    143:  ("IMAP",             MEDIUM, "Unencrypted email access."),
    443:  ("HTTPS",            INFO,   "Encrypted web server. Generally safe."),
    445:  ("SMB",              HIGH,   "Windows file sharing. Primary vector for ransomware spread."),
    1433: ("MSSQL",            HIGH,   "Microsoft SQL Server. Should never be publicly exposed."),
    1900: ("UPnP",             HIGH,   "Universal Plug and Play. Frequently exploited for amplification attacks."),
    3306: ("MySQL",            HIGH,   "Database port. Should never be publicly exposed."),
    3389: ("RDP",              HIGH,   "Remote Desktop. Primary brute-force target on Windows."),
    5900: ("VNC",              HIGH,   "Remote desktop. Often misconfigured with weak passwords."),
    8080: ("HTTP-Alt",         LOW,    "Alternate web port. Verify what is serving here."),
    8443: ("HTTPS-Alt",        LOW,    "Alternate HTTPS port."),
    27017:("MongoDB",          HIGH,   "Database port. Frequently found exposed with no authentication."),
}

def print_finding(risk, message):
    colour = RISK_COLOURS.get(risk, Fore.WHITE)
    print(f"  {colour}[{risk}]{Style.RESET_ALL} {message}")

def get_local_ip():
    """
    Gets the machine's local IP address by opening a dummy UDP socket
    to a public IP. The socket doesn't actually send data — we just
    need the OS to tell us which interface it would use, revealing
    our local IP. Closes immediately after.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_system_info():
    """
    Collects basic system information using Python's platform module.
    platform.node()    — computer hostname
    platform.system()  — OS name (Windows/Linux/Darwin)
    platform.release() — OS version
    platform.machine() — CPU architecture (AMD64, x86, ARM)
    """
    return {
        "hostname":     socket.gethostname(),
        "local_ip":     get_local_ip(),
        "os":           platform.system(),
        "os_version":   platform.release(),
        "architecture": platform.machine(),
        "scan_time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

def scan_open_ports(target_ip, port_range="1-1024"):
    """
    Uses nmap to scan the target IP for open ports within the given range.

    nm.scan() arguments:
      hosts   — the IP address to scan
      ports   — port range string e.g. "1-1024"
      arguments — nmap flags:
        -sV   → Service version detection (identifies WHAT is running on each port)
        -T4   → Timing template 4 (aggressive — faster scan, acceptable on local network)
        --open → Only report open ports (ignores filtered/closed)

    The result is a nested dictionary. We iterate through each host,
    then each protocol (tcp/udp), then each port to extract:
      - port number
      - state (open/closed/filtered)
      - service name
      - product (software name)
      - version number
    """
    print(f"\n{Fore.CYAN}[*] Scanning ports {port_range} on {target_ip}...{Style.RESET_ALL}")
    nm = nmap.PortScanner()

    findings = []
    try:
        nm.scan(hosts=target_ip, ports=port_range, arguments="-sV -T4 --open")

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state   = nm[host][proto][port]["state"]
                    service = nm[host][proto][port]["name"]
                    product = nm[host][proto][port]["product"]
                    version = nm[host][proto][port]["version"]

                    port_info = DANGEROUS_PORTS.get(port, None)

                    if port_info:
                        name, risk, explanation = port_info
                    else:
                        name        = service or "Unknown"
                        risk        = MEDIUM
                        explanation = "Unexpected open port. Verify this service is required."

                    detail = f"Port {port}/{proto.upper()} — {name}"
                    if product:
                        detail += f" ({product} {version}".strip() + ")"

                    findings.append({
                        "port":        port,
                        "protocol":    proto.upper(),
                        "state":       state,
                        "service":     name,
                        "product":     product,
                        "version":     version,
                        "risk":        risk,
                        "explanation": explanation,
                        "detail":      detail,
                    })
                    print_finding(risk, f"{detail} — {explanation}")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Port scan failed: {e}{Style.RESET_ALL}")

    return findings

def check_smb_exposure(local_ip):
    """
    Checks specifically whether SMB (port 445) is accessible.
    SMB is the Windows file sharing protocol and historically the
    primary vector for worm-style ransomware (WannaCry, NotPetya).

    Uses a raw socket connection attempt — if the connection succeeds,
    the port is open and accepting connections.

    socket.AF_INET  — IPv4 address family
    socket.SOCK_STREAM — TCP connection (as opposed to UDP)
    connect_ex()   — Like connect() but returns an error code instead
                     of raising an exception. 0 = success (port open).
    """
    findings = []
    print(f"\n{Fore.CYAN}[*] Checking SMB exposure (port 445)...{Style.RESET_ALL}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((local_ip, 445))
        s.close()
        if result == 0:
            findings.append({
                "check":       "SMB Port 445 Open",
                "risk":        HIGH,
                "explanation": "SMB is open on your local IP. Primary ransomware propagation vector. Disable if not needed via Windows Features.",
            })
            print_finding(HIGH, "SMB port 445 is OPEN — ransomware risk")
        else:
            findings.append({
                "check":       "SMB Port 445",
                "risk":        INFO,
                "explanation": "SMB port 445 is not accessible on your local IP. Good.",
            })
            print_finding(INFO, "SMB port 445 is closed — good")
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] SMB check error: {e}{Style.RESET_ALL}")
    return findings

def check_firewall_status():
    """
    On Windows, queries the firewall status using the netsh command.
    subprocess.run() executes a shell command from Python.

    Arguments:
      capture_output=True — captures stdout and stderr instead of printing
      text=True           — decodes bytes output to a string automatically
      shell=True          — runs via the shell (required for netsh on Windows)

    We check for the string "ON" in the output to determine
    whether the firewall is enabled for each network profile
    (Domain, Private, Public).
    """
    findings = []
    print(f"\n{Fore.CYAN}[*] Checking Windows Firewall status...{Style.RESET_ALL}")
    try:
        result = subprocess.run(
            "netsh advfirewall show allprofiles state",
            capture_output=True, text=True, shell=True
        )
        output = result.stdout

        profiles = ["Domain", "Private", "Public"]
        lines    = output.splitlines()

        for i, line in enumerate(lines):
            for profile in profiles:
                if profile in line:
                    state_line = lines[i + 1] if i + 1 < len(lines) else ""
                    if "ON" in state_line.upper():
                        findings.append({
                            "check":       f"Firewall — {profile} Profile",
                            "risk":        INFO,
                            "explanation": f"{profile} profile firewall is ON. Good.",
                        })
                        print_finding(INFO, f"Firewall {profile} profile: ON")
                    else:
                        findings.append({
                            "check":       f"Firewall — {profile} Profile",
                            "risk":        HIGH,
                            "explanation": f"{profile} profile firewall is OFF. Immediate risk — enable via Windows Security.",
                        })
                        print_finding(HIGH, f"Firewall {profile} profile: OFF — enable immediately")
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] Firewall check error: {e}{Style.RESET_ALL}")
    return findings

def check_wifi_networks():
    """
    Uses the netsh wlan command to list visible Wi-Fi networks nearby.
    We look specifically for networks using WEP or OPEN (no password)
    security — both are trivially broken.

    WEP (Wired Equivalent Privacy) was deprecated in 2004 and can be
    cracked in minutes using freely available tools. Any network
    still using WEP should be treated as completely compromised.

    OPEN networks have no encryption — all traffic is readable by
    anyone on the same network or within radio range.
    """
    findings = []
    print(f"\n{Fore.CYAN}[*] Checking nearby Wi-Fi networks for weak security...{Style.RESET_ALL}")
    try:
        result = subprocess.run(
            "netsh wlan show networks mode=bssid",
            capture_output=True, text=True, shell=True
        )
        output = result.stdout

        current_ssid = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current_ssid = parts[1].strip()
            elif "Authentication" in line:
                auth = line.split(":", 1)[-1].strip()
                if "Open" in auth or "WEP" in auth:
                    findings.append({
                        "check":       f"Wi-Fi: {current_ssid}",
                        "risk":        HIGH,
                        "explanation": f"Network '{current_ssid}' uses {auth} security — trivially interceptable. Avoid connecting.",
                    })
                    print_finding(HIGH, f"Weak Wi-Fi detected: {current_ssid} ({auth})")

        if not findings:
            print_finding(INFO, "No open or WEP networks detected nearby")

    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] Wi-Fi check error: {e}{Style.RESET_ALL}")
    return findings

def run_audit():
    """
    Master function that runs all audit checks in sequence.
    Returns a single dictionary containing all findings and
    system info — this gets passed to the report generator.
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  SECURECHECK — Personal Security Audit")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    system_info   = get_system_info()
    local_ip      = system_info["local_ip"]

    print(f"{Fore.WHITE}System: {system_info['hostname']} "
          f"({system_info['os']} {system_info['os_version']}) "
          f"| IP: {local_ip}{Style.RESET_ALL}")

    port_findings     = scan_open_ports(local_ip)
    smb_findings      = check_smb_exposure(local_ip)
    firewall_findings = check_firewall_status()
    wifi_findings     = check_wifi_networks()

    all_findings = port_findings + smb_findings + firewall_findings + wifi_findings

    high_count   = sum(1 for f in all_findings if f.get("risk") == HIGH)
    medium_count = sum(1 for f in all_findings if f.get("risk") == MEDIUM)
    low_count    = sum(1 for f in all_findings if f.get("risk") == LOW)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  AUDIT COMPLETE")
    print(f"  {Fore.RED}{high_count} HIGH  "
          f"{Fore.YELLOW}{medium_count} MEDIUM  "
          f"{Fore.GREEN}{low_count} LOW")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    return {
        "system_info":      system_info,
        "port_findings":    port_findings,
        "smb_findings":     smb_findings,
        "firewall_findings":firewall_findings,
        "wifi_findings":    wifi_findings,
        "all_findings":     all_findings,
        "summary": {
            "high":   high_count,
            "medium": medium_count,
            "low":    low_count,
            "total":  len(all_findings),
        }
    }