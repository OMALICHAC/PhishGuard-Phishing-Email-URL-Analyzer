#!/usr/bin/env python3
"""
PhishGuard - Phishing Email & URL Analyzer
============================================
A beginner-friendly Python tool that analyzes emails and URLs
to detect phishing attempts. It checks for suspicious patterns,
fake headers, known phishing indicators, and domain reputation.

Usage:
    Interactive mode:  python phishguard.py
    Analyze URL:       python phishguard.py --url "https://suspicious-link.com"
    Analyze email:     python phishguard.py --email suspicious_email.eml
    Bulk analyze:      python phishguard.py --bulk urls.txt
    Save report:       python phishguard.py --url "https://example.com" --report

Author: Chioma Iroka
License: MIT
"""

import argparse
import os
import sys

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = WHITE = BLUE = ""
        LIGHTRED_EX = LIGHTYELLOW_EX = LIGHTGREEN_EX = ""
        LIGHTCYAN_EX = LIGHTMAGENTA_EX = LIGHTWHITE_EX = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

try:
    from tqdm import tqdm
except ImportError:
    # Fallback: simple progress indicator
    def tqdm(iterable, **kwargs):
        desc = kwargs.get("desc", "Processing")
        items = list(iterable)
        total = len(items)
        for i, item in enumerate(items):
            print(f"\r  {desc}... {i+1}/{total}", end="", flush=True)
            yield item
        print()

from url_analyzer import analyze_url
from email_analyzer import analyze_email
from report_generator import generate_text_report, generate_html_report, save_report

VERSION = "1.0.0"

# ============================================================
# Display Functions
# ============================================================

def print_banner():
    """Display the PhishGuard welcome banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║         ░█▀█░█░█░▀█▀░█▀▀░█░█░█▀▀░█░█░█▀█░█▀▄   ║
    ║         ░█▀▀░█▀█░░█░░▀▀█░█▀█░█░█░█░█░█▀█░█▀▄   ║
    ║         ░▀░░░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀   ║
    ║                                                  ║
    ║      Phishing Email & URL Analyzer v{VERSION}       ║
    ║      Detect phishing with confidence             ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def print_menu():
    """Display the main interactive menu."""
    print(f"""
{Fore.WHITE}{Style.BRIGHT}    ╔══════════════════════════════════════╗
    ║        PhishGuard v{VERSION}             ║
    ║      Phishing Detection Tool         ║
    ╠══════════════════════════════════════╣
    ║                                      ║
    ║  {Fore.CYAN}1.{Fore.WHITE} Analyze a URL                   ║
    ║  {Fore.CYAN}2.{Fore.WHITE} Analyze an email file (.eml)    ║
    ║  {Fore.CYAN}3.{Fore.WHITE} Bulk analyze (multiple URLs)    ║
    ║  {Fore.CYAN}4.{Fore.WHITE} View help / how to use          ║
    ║  {Fore.CYAN}5.{Fore.WHITE} Exit                            ║
    ║                                      ║
    ╚══════════════════════════════════════╝
{Style.RESET_ALL}""")


def print_help():
    """Display help information about using PhishGuard."""
    print(f"""
{Fore.CYAN}{Style.BRIGHT}═══ PhishGuard Help ═══{Style.RESET_ALL}

{Fore.WHITE}{Style.BRIGHT}What does PhishGuard do?{Style.RESET_ALL}
  PhishGuard analyzes URLs and email files to detect phishing attempts.
  It checks for suspicious patterns and gives each target a risk score
  from 0 (safe) to 100 (definitely phishing).

{Fore.WHITE}{Style.BRIGHT}How to use:{Style.RESET_ALL}

  {Fore.CYAN}Interactive mode:{Style.RESET_ALL}
    python phishguard.py
    (Follow the menu prompts)

  {Fore.CYAN}Command line:{Style.RESET_ALL}
    python phishguard.py --url "https://suspicious-link.com"
    python phishguard.py --email suspicious_email.eml
    python phishguard.py --bulk urls_to_check.txt
    python phishguard.py --url "https://example.com" --report

{Fore.WHITE}{Style.BRIGHT}Understanding Risk Scores:{Style.RESET_ALL}
  {Fore.GREEN}  0-20:  LOW RISK       - Likely legitimate{Style.RESET_ALL}
  {Fore.YELLOW} 21-40:  MODERATE RISK  - Some suspicious elements{Style.RESET_ALL}
  {Fore.LIGHTYELLOW_EX} 41-60:  HIGH RISK      - Multiple phishing indicators{Style.RESET_ALL}
  {Fore.RED} 61-80:  VERY HIGH      - Strong phishing indicators{Style.RESET_ALL}
  {Fore.MAGENTA} 81-100: CRITICAL       - Almost certainly phishing{Style.RESET_ALL}

{Fore.WHITE}{Style.BRIGHT}Email File Format:{Style.RESET_ALL}
  PhishGuard analyzes .eml files (standard email format).
  You can export/save emails as .eml from most email clients.
  Sample emails are provided in the sample_emails/ directory.

{Fore.WHITE}{Style.BRIGHT}Reports:{Style.RESET_ALL}
  Use --report flag to save analysis results as text and HTML files.
  Reports are saved in the current directory.
""")


def display_results(risk_score):
    """
    Display analysis results in the terminal with colour coding.

    Args:
        risk_score: RiskScore object with analysis results
    """
    summary = risk_score.get_summary()

    # Colour mapping
    color_map = {
        "green":   Fore.GREEN,
        "yellow":  Fore.YELLOW,
        "orange":  Fore.LIGHTYELLOW_EX,
        "red":     Fore.RED,
        "magenta": Fore.MAGENTA,
    }
    risk_color = color_map.get(summary["risk_color"], Fore.WHITE)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 60}")
    print(f"  ANALYSIS RESULTS")
    print(f"{'═' * 60}{Style.RESET_ALL}")

    print(f"\n  Target: {Fore.WHITE}{Style.BRIGHT}{summary['target']}{Style.RESET_ALL}")
    print(f"  Type:   {summary['analysis_type'].upper()} Analysis")

    # Risk Score Display
    print(f"\n  {risk_color}{Style.BRIGHT}{'─' * 50}")
    print(f"  {summary['risk_icon']}  RISK LEVEL: {summary['risk_level']}")
    print(f"  Score: {summary['score_bar']}")
    print(f"  {summary['risk_description']}")
    print(f"  Confidence: {summary['confidence']} ({summary['confidence_percentage']}%)")
    print(f"  {'─' * 50}{Style.RESET_ALL}")

    # Findings
    if summary["findings"]:
        print(f"\n  {Fore.WHITE}{Style.BRIGHT}Findings ({summary['findings_count']}):{Style.RESET_ALL}")
        for i, finding in enumerate(summary["findings"], 1):
            points_color = Fore.RED if finding["points"] >= 20 else (
                Fore.YELLOW if finding["points"] >= 10 else Fore.GREEN
            )
            print(f"\n  {Fore.CYAN}[{i}]{Style.RESET_ALL} {finding['description']}")
            print(f"      {Style.DIM}Category: {finding['category']} | "
                  f"Risk: {points_color}+{finding['points']} pts{Style.RESET_ALL}")
            # Wrap long explanations
            explanation = finding["explanation"]
            if len(explanation) > 80:
                words = explanation.split()
                line = "      "
                for word in words:
                    if len(line) + len(word) + 1 > 80:
                        print(f"{Style.DIM}{line}{Style.RESET_ALL}")
                        line = "      " + word
                    else:
                        line += " " + word if line.strip() else "      " + word
                if line.strip():
                    print(f"{Style.DIM}{line}{Style.RESET_ALL}")
            else:
                print(f"      {Style.DIM}{explanation}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}No suspicious indicators detected.{Style.RESET_ALL}")

    # Recommendations
    if summary["recommendations"]:
        print(f"\n  {Fore.WHITE}{Style.BRIGHT}Recommendations:{Style.RESET_ALL}")
        for rec in summary["recommendations"]:
            print(f"  {Fore.YELLOW}*{Style.RESET_ALL} {rec}")

    print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")


# ============================================================
# Analysis Functions
# ============================================================

def analyze_url_interactive():
    """Handle URL analysis in interactive mode."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}═══ URL Analysis ═══{Style.RESET_ALL}")
    url = input(f"\n  {Fore.WHITE}Enter URL to analyze: {Style.RESET_ALL}").strip()

    if not url:
        print(f"  {Fore.RED}No URL provided.{Style.RESET_ALL}")
        return

    print(f"\n  {Fore.CYAN}Analyzing URL...{Style.RESET_ALL}")
    risk_score = analyze_url(url)
    display_results(risk_score)

    # Offer to save report
    _offer_save_report(risk_score)


def analyze_email_interactive():
    """Handle email analysis in interactive mode."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}═══ Email Analysis ═══{Style.RESET_ALL}")
    filepath = input(f"\n  {Fore.WHITE}Enter path to .eml file: {Style.RESET_ALL}").strip()

    if not filepath:
        print(f"  {Fore.RED}No file path provided.{Style.RESET_ALL}")
        return

    if not os.path.exists(filepath):
        print(f"  {Fore.RED}File not found: {filepath}{Style.RESET_ALL}")
        return

    if not filepath.lower().endswith(".eml"):
        print(f"  {Fore.YELLOW}Warning: File does not have .eml extension.{Style.RESET_ALL}")

    print(f"\n  {Fore.CYAN}Analyzing email...{Style.RESET_ALL}")
    risk_score = analyze_email(filepath)
    display_results(risk_score)

    _offer_save_report(risk_score)


def analyze_bulk_interactive():
    """Handle bulk URL analysis in interactive mode."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}═══ Bulk URL Analysis ═══{Style.RESET_ALL}")
    filepath = input(f"\n  {Fore.WHITE}Enter path to file with URLs (one per line): {Style.RESET_ALL}").strip()

    if not filepath:
        print(f"  {Fore.RED}No file path provided.{Style.RESET_ALL}")
        return

    if not os.path.exists(filepath):
        print(f"  {Fore.RED}File not found: {filepath}{Style.RESET_ALL}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not urls:
        print(f"  {Fore.RED}No URLs found in file.{Style.RESET_ALL}")
        return

    print(f"\n  {Fore.CYAN}Analyzing {len(urls)} URL(s)...{Style.RESET_ALL}\n")

    results = []
    for url in tqdm(urls, desc="  Analyzing"):
        risk_score = analyze_url(url)
        results.append(risk_score)

    # Display summary table
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 70}")
    print(f"  BULK ANALYSIS RESULTS")
    print(f"{'═' * 70}{Style.RESET_ALL}")
    print(f"\n  {'URL':<45} {'Score':>6} {'Risk Level':<15}")
    print(f"  {'─' * 45} {'─' * 6} {'─' * 15}")

    for risk_score in results:
        summary = risk_score.get_summary()
        url_display = summary["target"][:43] + ".." if len(summary["target"]) > 45 else summary["target"]

        color_map = {
            "green":   Fore.GREEN,
            "yellow":  Fore.YELLOW,
            "orange":  Fore.LIGHTYELLOW_EX,
            "red":     Fore.RED,
            "magenta": Fore.MAGENTA,
        }
        color = color_map.get(summary["risk_color"], Fore.WHITE)

        print(f"  {url_display:<45} {color}{summary['total_score']:>4}/100{Style.RESET_ALL} "
              f"{color}{summary['risk_level']:<15}{Style.RESET_ALL}")

    print(f"\n  Total URLs analyzed: {len(results)}")
    high_risk = sum(1 for r in results if r.total_score > 40)
    print(f"  High risk or above:  {Fore.RED}{high_risk}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")

    # Offer to save reports
    save = input(f"  {Fore.WHITE}Save reports for all URLs? (y/n): {Style.RESET_ALL}").strip().lower()
    if save == "y":
        os.makedirs("bulk_reports", exist_ok=True)
        for risk_score in results:
            save_report(risk_score, output_dir="bulk_reports", fmt="html")
        print(f"  {Fore.GREEN}Reports saved in bulk_reports/ directory.{Style.RESET_ALL}")


def _offer_save_report(risk_score):
    """Ask user if they want to save the report."""
    save = input(f"  {Fore.WHITE}Save report? (y/n): {Style.RESET_ALL}").strip().lower()
    if save == "y":
        files = save_report(risk_score, fmt="both")
        for f in files:
            print(f"  {Fore.GREEN}Saved: {f}{Style.RESET_ALL}")


# ============================================================
# Command-Line Interface
# ============================================================

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PhishGuard - Phishing Email & URL Analyzer",
        epilog="Examples:\n"
               "  python phishguard.py --url \"https://suspicious.com\"\n"
               "  python phishguard.py --email suspicious.eml\n"
               "  python phishguard.py --bulk urls.txt --report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--url", "-u",
        help="URL to analyze for phishing indicators",
    )
    parser.add_argument(
        "--email", "-e",
        help="Path to .eml email file to analyze",
    )
    parser.add_argument(
        "--bulk", "-b",
        help="Path to file containing URLs (one per line) for bulk analysis",
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Save analysis report (text and HTML)",
    )

    return parser.parse_args()


def run_cli(args):
    """Run PhishGuard in command-line mode."""
    if args.url:
        print(f"\n  {Fore.CYAN}Analyzing URL: {args.url}{Style.RESET_ALL}")
        risk_score = analyze_url(args.url)
        display_results(risk_score)

        if args.report:
            files = save_report(risk_score, fmt="both")
            for f in files:
                print(f"  {Fore.GREEN}Report saved: {f}{Style.RESET_ALL}")

    elif args.email:
        if not os.path.exists(args.email):
            print(f"  {Fore.RED}Error: File not found: {args.email}{Style.RESET_ALL}")
            sys.exit(1)

        print(f"\n  {Fore.CYAN}Analyzing email: {args.email}{Style.RESET_ALL}")
        risk_score = analyze_email(args.email)
        display_results(risk_score)

        if args.report:
            files = save_report(risk_score, fmt="both")
            for f in files:
                print(f"  {Fore.GREEN}Report saved: {f}{Style.RESET_ALL}")

    elif args.bulk:
        if not os.path.exists(args.bulk):
            print(f"  {Fore.RED}Error: File not found: {args.bulk}{Style.RESET_ALL}")
            sys.exit(1)

        with open(args.bulk, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        print(f"\n  {Fore.CYAN}Analyzing {len(urls)} URL(s)...{Style.RESET_ALL}")
        for url in tqdm(urls, desc="  Analyzing"):
            risk_score = analyze_url(url)
            display_results(risk_score)

            if args.report:
                os.makedirs("bulk_reports", exist_ok=True)
                save_report(risk_score, output_dir="bulk_reports", fmt="html")

        if args.report:
            print(f"\n  {Fore.GREEN}Reports saved in bulk_reports/ directory.{Style.RESET_ALL}")


def run_interactive():
    """Run PhishGuard in interactive mode."""
    print_banner()

    while True:
        print_menu()
        choice = input(f"  {Fore.CYAN}Select option (1-5): {Style.RESET_ALL}").strip()

        if choice == "1":
            analyze_url_interactive()
        elif choice == "2":
            analyze_email_interactive()
        elif choice == "3":
            analyze_bulk_interactive()
        elif choice == "4":
            print_help()
        elif choice == "5":
            print(f"\n  {Fore.CYAN}Thank you for using PhishGuard! Stay safe. {Style.RESET_ALL}\n")
            break
        else:
            print(f"  {Fore.RED}Invalid choice. Please enter 1-5.{Style.RESET_ALL}")


# ============================================================
# Main Entry Point
# ============================================================

def main():
    """Main entry point for PhishGuard."""
    args = parse_arguments()

    # If any CLI arguments provided, run in CLI mode
    if args.url or args.email or args.bulk:
        print_banner()
        run_cli(args)
    else:
        # Otherwise, run in interactive mode
        run_interactive()


if __name__ == "__main__":
    main()
