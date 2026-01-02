# ZeroDay USB Forge
### ⚡ USB Payload Crafting Framework for Red-Team Operations

ZeroDay USB Forge — Red-Team Payload Builder

ZeroDay USB Forge is a **USB-based payload crafting system** built for:

- Offensive security research  
- Penetration testing  
- Red-team engagements  
- Rapid payload deployment in the field

It auto-builds structured payload packages, generates Windows/Linux/macOS installers, organizes operational files, and prepares USB drives for real-world offensive simulations.

---

## 🔥 Features

- **Cross-platform payload packaging**
  - Windows EXE payloads  
  - Linux payloads  
  - macOS application stubs  

- **Automatic folder structure generation**
  - `/payloads/`
  - `/docs/`
  - `/installers/`
  - `/resources/`

- **Metasploit-integrated payload support**
  - msfvenom / staged payload drops  
  - Auto-handler config templates  
  - Auto-generated README instructions

- **Script sanitizer & auto-repair engine**
  - Removes Unicode, HTML fragments, emojis  
  - Repairs malformed Python payload scripts  
  - AST-based syntax cleanup

- **Recon artifact organizer**
  - Sorts recon dump files into:
    - images  
    - videos  
    - endpoints  
    - messages  
    - javascript  
    - urls  
    - subdomains  
  - Generates clean `summary.txt` files per scan

- **Operator-friendly output**
  - Clean directory structure  
  - Human-readable instructions  
  - Ready for drop deployment on real USB devices  

---
ZeroDay-USB-Forge/
├── forge.py # Main builder engine
├── sanitizer/
│ ├── fix_python.py # Repairs malformed Python payloads
│ ├── unicode_clean.py # Strips emojis + box characters
│ └── html_clean.py # Removes injected HTML
├── recon/
│ ├── recon_organizer.py # Sorts recon dumps into categories
│ └── templates/
│ └── zero_report.md # Template for recon summary
├── templates/
│ ├── windows_installer.ps1 # Dropper installer (Windows)
│ ├── linux_install.sh # Dropper installer (Linux)
│ ├── macos_install.sh # macOS dropper
│ └── readme_template.txt # Auto-generated field instructions
├── payloads/
│ └── (auto-generated)
├── installers/
│ └── (auto-generated)
├── docs/
│ └── (auto-generated)
└── README.md

---

## 🛠️ Installation (Kali Linux Recommended)

```bash
https://github.com/Panda1847/ZeroDay-USB-Expliot-Forge.git
cd ZeroDay-USB-Forge
sudo apt update
sudo apt install -y python3 python3-pip python3-venv metasploit-framework
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Usage
1. Build a new USB payload package
python3 forge.py --output /media/usb/


This will:

Generate a new payload suite

Create OS-specific installers

Produce a clean README in /docs

Build structured folders ready for deployment

2. Organize recon output
python3 recon/recon_organizer.py path/to/recon.log MyScanName


This generates:

Desktop/ReconScans/MyScanName/
├── images/
├── videos/
├── endpoints/
├── javascript/
├── urls/
├── subdomains/
└── reports/summary.txt

3. Sanitize corrupted Python payloads
python3 sanitizer/fix_python.py payload.py


Repairs:

Syntax errors

Emojis

Unicode

HTML fragments

Box drawing junk

Hidden control characters

⚠️ Legal Disclaimer

ZeroDay USB Forge is for:

Authorized penetration testing

Red-team training

Security research

Personal lab use

Do NOT use this tool on machines you do not own or have explicit written permission to test.
Misuse may violate local, national, or international laws.

⭐ Roadmap

Web GUI

Plugin system

Auto-Metasploit handler launcher

File encryption for USB drops

Covert execution templates

AI-powered payload audit engine

🤝 Contributing

Pull requests are welcome — especially:

New installer templates

New recon parsing modules

Payload structuring improvements


## 📁 Project Structure

