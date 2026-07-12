"""
Terminal UI: colors, banners, status line printers, threat badges.
No network or DB logic lives here — this module only prints.
"""


class C:
    RESET = "\033[0m";   BOLD  = "\033[1m"
    RED   = "\033[91m";  GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE  = "\033[94m";  MAG   = "\033[95m"; CYAN   = "\033[96m"
    WHITE = "\033[97m";  GRAY  = "\033[90m"


def cprint(text, color=C.WHITE, bold=False):
    print(f"{''+C.BOLD if bold else ''}{color}{text}{C.RESET}")


def banner():
    print(f"""
{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════════════════╗
  ║   ██████╗██╗   ██╗██████╗ ███████╗██████╗     ███████╗ ██████╗  ██████╗  ║
  ║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔═══██╗██╔════╝  ║
  ║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ███████╗██║   ██║██║       ║
  ║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ╚════██║██║   ██║██║       ║
  ║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ███████║╚██████╔╝╚██████╔╝ ║
  ║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝  ║
  ║                                                                            ║
  ║   {C.YELLOW}AI SOC ANALYZER v3.0  ·  CYBER SENTINEL{C.CYAN}                            ║
  ║   {C.GRAY}SQLite · Threat Intel · ARP Detection · Telegram · Email{C.CYAN}            ║
  ╚══════════════════════════════════════════════════════════════════════════╝{C.RESET}
""")


def section_header(title: str, icon: str = "▸"):
    w = 66
    print(f"\n{C.CYAN}{'─'*w}{C.RESET}")
    cprint(f"  {icon}  {title}", C.CYAN, bold=True)
    print(f"{C.CYAN}{'─'*w}{C.RESET}")


def status_ok(msg):    cprint(f"  ✅  {msg}", C.GREEN)
def status_warn(msg):  cprint(f"  ⚠️   {msg}", C.YELLOW)
def status_err(msg):   cprint(f"  ❌  {msg}", C.RED)
def status_info(msg):  cprint(f"  ℹ️   {msg}", C.BLUE)
def status_alert(msg): cprint(f"  🚨  {msg}", C.RED, bold=True)


def threat_badge(score: int) -> str:
    if score >= 70: return f"{C.RED}{C.BOLD}[CRITICAL {score:3d}]{C.RESET}"
    if score >= 40: return f"{C.YELLOW}{C.BOLD}[HIGH     {score:3d}]{C.RESET}"
    if score >= 15: return f"{C.BLUE}[MEDIUM   {score:3d}]{C.RESET}"
    return             f"{C.GREEN}[LOW      {score:3d}]{C.RESET}"


def threat_color(score: int) -> str:
    if score >= 70: return C.RED
    if score >= 40: return C.YELLOW
    if score >= 15: return C.BLUE
    return C.GREEN


def print_threat_table(devices: list):
    section_header("DEVICE THREAT LEADERBOARD", "🎯")
    hdr = (f"  {'IP':<18} {'HOSTNAME':<22} {'VENDOR':<20} "
           f"{'COUNTRY':<9} {'SCORE':<16} ABUSE")
    cprint(hdr, C.GRAY)
    cprint("  " + "─"*84, C.GRAY)
    for d in sorted(devices, key=lambda x: x.get("threat_score", 0), reverse=True):
        score   = d.get("threat_score", 0)
        abuse   = d.get("abuse_score",  0)
        ip      = str(d.get("ip", "?"))
        host    = str(d.get("hostname") or "—")[:21]
        vendor  = str(d.get("vendor")   or "—")[:19]
        country = str(d.get("country")  or "—")[:8]
        badge   = threat_badge(score)
        col     = threat_color(score)
        abuse_s = (f"{C.RED}{abuse}%{C.RESET}" if abuse > 0
                   else f"{C.GRAY}0%{C.RESET}")
        print(f"  {col}{ip:<18}{C.RESET} {host:<22} {vendor:<20} "
              f"{country:<9} {badge} {abuse_s}")
    cprint("  " + "─"*84, C.GRAY)
