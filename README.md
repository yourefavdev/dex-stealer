# dex-stealer
token and browser stealer example

UPDATE NEW STEALER V2
Recent Changes to Stealer Functionality:

Added Functions:
Startup Persistence: Functionality to add the script to Windows startup via the registry was implemented.
Expanded Browser Support (for Passwords & History):
Support was explicitly added/confirmed for: Brave and Vivaldi, in addition to existing support for Chrome, Edge, and Opera (including Opera GX).
Removed Functions (from the core stealer.py to be made optional by the builder):
Cookie Stealer: The dedicated cookie stealing functionality (cookies_grabber_mod and its direct calls/outputs) was removed from the main stealer script, with the intention that the builder could optionally re-include it if the stealer_template.py is prepared with markers for cookie code.

Disclaimer

This project is intended for ethical purposes only. The use of this software is strictly prohibited for malicious purposes, unauthorized data collection, or unauthorized access to any systems or personal data. The developer, Dex/D3xoncpvp, will not be held responsible for any misuse of this project. Unauthorized selling, distribution, or modification of this source code is also strictly prohibited.

About the Project

This tool is developed to demonstrate techniques for data collection in controlled environments and to provide insights into data security and information gathering. It is meant for educational and ethical testing purposes only.

For support, contact:

Discord: d3xonv3

Features

Collection of browser data (passwords and browsing history) from Chrome, Edge, and Opera.

Extraction of Discord tokens.

System information gathering (OS, architecture, RAM).

Optional upload of collected data to GoFile.

Notification via Discord webhook.

Requirements

Python 3.7+

pycryptodome for AES encryption

psutil for system information gathering

requests for HTTP requests

win32crypt for decrypting browser data

Installation

Clone the repository:

git clone <repository-url>
cd <repository-folder>

Install the required libraries:

pip install -r requirements.txt

Configure the webhook URL in the script:

DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"

Usage

Run the script:

python main.py

Legal Notice

Unauthorized use of this script to access or exfiltrate data from systems without proper authorization is illegal and against the terms of service of most platforms. Ensure you have proper consent and legal rights to access any data using this tool.

License

This project is licensed under the MIT License. Unauthorized selling or distribution of this project is strictly prohibited.
![2025-05-17 20_48_01-NVIDIA GeForce Overlay DT](https://github.com/user-attachments/assets/ea9413ca-c6e3-44dc-bc85-c43348e1a2e8)
