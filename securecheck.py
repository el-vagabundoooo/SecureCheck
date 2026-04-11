import sys
import os
from colorama import Fore, Style, init

init(autoreset=True)

from modules.audit    import run_audit
from modules.phishing import run_phishing_analysis
from modules.report   import generate_report

BANNER = f"""
{Fore.RED}
  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
{Fore.WHITE}         ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
        ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
        ██║     ███████║█████╗  ██║     █████╔╝
        ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
        ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
         ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
{Style.RESET_ALL}
  Personal Security Audit & Phishing Email Analyzer
  For educational use · Scan only systems you own
"""

MENU = f"""
{Fore.CYAN}  What would you like to do?

  {Fore.WHITE}[1]{Fore.CYAN} Run Security Audit (scan this machine)
  {Fore.WHITE}[2]{Fore.CYAN} Analyse a Phishing Email
  {Fore.WHITE}[3]{Fore.CYAN} Run Both (full report)
  {Fore.WHITE}[4]{Fore.CYAN} Exit
{Style.RESET_ALL}"""

def get_email_input():
    """
    Collects a raw email from the user by reading multiple lines
    until they type 'END' on its own line.

    sys.stdin.readline() reads one line at a time including
    the newline character. We strip() each line and join with
    newlines to rebuild the full email text.

    This approach handles emails with blank lines (which a simple
    input() loop would misinterpret as the end of input).
    """
    print(f"\n{Fore.CYAN}Paste the raw email below.")
    print(f"Include headers if available (From:, Subject:, Received:, etc.)")
    print(f"Type {Fore.WHITE}END{Fore.CYAN} on a new line when done:{Style.RESET_ALL}\n")

    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except EOFError:
            break

    return "\n".join(lines)

def main():
    print(BANNER)

    while True:
        print(MENU)
        choice = input(f"  {Fore.WHITE}Enter choice (1-4): {Style.RESET_ALL}").strip()

        if choice == "1":
            audit_data = run_audit()
            filepath   = generate_report(audit_data=audit_data)
            open_report(filepath)

        elif choice == "2":
            raw_email    = get_email_input()
            phishing_data = run_phishing_analysis(raw_email)
            filepath      = generate_report(phishing_data=phishing_data)
            open_report(filepath)

        elif choice == "3":
            audit_data   = run_audit()
            raw_email    = get_email_input()
            phishing_data = run_phishing_analysis(raw_email)
            filepath      = generate_report(audit_data=audit_data,
                                            phishing_data=phishing_data)
            open_report(filepath)

        elif choice == "4":
            print(f"\n{Fore.CYAN}Exiting SecureCheck. Stay secure.{Style.RESET_ALL}\n")
            sys.exit(0)

        else:
            print(f"{Fore.RED}  Invalid choice. Enter 1, 2, 3, or 4.{Style.RESET_ALL}")

def open_report(filepath):
    """
    Opens the generated HTML report in the default browser.
    os.startfile() is Windows-specific — it opens a file with
    whatever application is associated with that file type,
    exactly like double-clicking it in Explorer.
    The abspath() call converts a relative path to absolute
    so the browser can locate the file correctly.
    """
    abs_path = os.path.abspath(filepath)
    print(f"{Fore.GREEN}Opening report in browser...{Style.RESET_ALL}")
    os.startfile(abs_path)

if __name__ == "__main__":
    """
    __name__ == "__main__" is True only when this file is run directly
    (e.g. python securecheck.py). It is False when the file is imported
    as a module by another script. This guard prevents main() from
    running automatically if someone imports securecheck in another script.
    """
    main()