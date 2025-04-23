PhishiUrl - Phishing Detection and Simulation Tool
PhishiUrl is a powerful tool for detecting and simulating phishing attacks, designed to assist cybersecurity professionals and penetration testers in identifying and mitigating vulnerabilities. With a variety of features, including homoglyph URL generation, website cloning, and URL security analysis, this tool is built for ethical security testing.
Current Version: 1.2.8Author: EmadGitHub Repository: github.com/EmadYaY/PhishiUrl

⚠️ Legal Warning
Using this tool for illegal purposes, such as stealing data or conducting real phishing attacks, is strictly prohibited. PhishiUrl is intended solely for legal penetration testing with explicit permission from the website owner. Any unauthorized use is the user's responsibility.

✨ Features
Version 1.2.8

Advanced Phishing Detection:
Identifies homoglyph characters in URLs.
Detects suspicious keywords (e.g., login, verify).
Integrates with VirusTotal and PhishTank APIs for URL security analysis.


Phishing URL Generation:
Suggests homoglyph domains by replacing characters with lookalikes (e.g., 'o' with 'о').
Checks domain availability using WHOIS.


Website Cloning:
Clones web pages by downloading resources (HTML, CSS, JS, images).
--download-js option to download JavaScript files.
--download-all option to download all assets (images, fonts, etc.).
Captures user input data (e.g., username, password) upon form submission.
Automatically redirects to the original domain after capturing data.


Iframe Mode:
Displays the original site in an iframe while capturing user data silently.
--use-iframe option to enable iframe mode instead of cloning.


Tunneling with Ngrok:
Creates a tunnel with Ngrok for remote access to the fake page.
Generates a QR code for quick access to the tunnel URL.


Hosts File Management:
Modifies the Windows hosts file to map homoglyph domains locally (requires Administrator privileges).


Reporting:
Generates detailed reports for URL analysis and captured data in report.json and credentials.txt.
Optional keylogging data saved in keylog.txt (in iframe mode).




🛠️ Prerequisites
To use PhishiUrl, you need to install the following:

Python 3.7 or higher

Google Chrome (for Selenium)

ChromeDriver (matching your Chrome version)

Dependencies:
pip install click rich requests pyngrok python-whois qrcode beautifulsoup4 lxml pywin32 selenium


Ngrok Token: For tunneling (add to config.json).

VirusTotal API Key: For URL analysis (optional, add to config.json).



📦 Installation

Clone the repository:
git clone https://github.com/EmadYaY/PhishiUrl.git
cd PhishiUrl


Create and activate a virtual environment:
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows


Install the dependencies:
pip install .


Configure config.json:
{
    "ngrok_token": "YOUR_NGROK_TOKEN",
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "phishtank_api_key": "",
    "templates_path": "./templates"
}




🚀 Commands and Usage
PhishiUrl uses a command-line interface (CLI). Below are the main commands and examples:
1. Check URLs for Phishing
Detect suspicious URLs using homoglyphs, keywords, and external APIs.
phishiurl check --url faceb00k.com


With a file:
phishiurl check --file urls.txt --output results.json



2. Start a Tunnel and Web Server
Tunnel a phishing page with Ngrok and start a local server.
phishiurl tunnel --port 8080 --template instagram_login.html

3. Suggest Homoglyph Domains
Generate similar domains using homoglyph characters.
phishiurl suggest --domain google.com --check-availability

4. Check URLs with External APIs
Analyze a URL using VirusTotal or PhishTank.
phishiurl api_check --url faceb00k.com --service virustotal

5. Clone a Website or Use Iframe
Clone a website, use local files, or display in an iframe, capture user data, and serve it locally or remotely.

Clone with all assets:
phishiurl clone --url https://voorivex.academy/login --port 8080 --use-ngrok --download-js --download-all


Use iframe mode:
phishiurl clone --url https://voorivex.academy/login --port 8080 --use-ngrok --use-iframe


Clone from local files:
phishiurl clone --local-folder ./my_website --port 8080



6. Show Help
View the list of all commands and examples.
phishiurl help


🧪 Testing the Tool
To test the features of version 1.2.8, follow these steps:
Test Website Cloning

Open a terminal with Administrator privileges (Windows):
Start-Process powershell -Verb runAs


Activate the virtual environment:
cd /path/to/PhishiUrl
.\venv\Scripts\Activate.ps1


Run the clone command:
phishiurl clone --url https://voorivex.academy/login/ --port 8080 --use-ngrok --download-js --download-all


When prompted, select url:
Do you want to clone from the URL, use local files, or use iframe? (url/local/iframe) [url]: url


Check the output:

The page should open in the browser (e.g., http://voorivex.аcаdemy:8080).
The page should look similar to the original site (CSS, JS, images, and fonts loaded).
Entered data (e.g., username, password) should be saved in templates/cloned/voorivex_аcаdemy/credentials.txt.



Test Iframe Mode

Run the clone command with iframe:
phishiurl clone --url https://voorivex.academy/login/ --port 8080 --use-ngrok --use-iframe


When prompted, select iframe:
Do you want to clone from the URL, use local files, or use iframe? (url/local/iframe) [iframe]: iframe


Check the output:

The page should display the original site in an iframe.
Entered data should be captured in credentials.txt.
Keylogging data (if enabled) should be saved in keylog.txt.



Test Homglyph Domain Generation

Run the following command:
phishiurl suggest --domain google.com --check-availability


The output should display a list of homoglyph domains, e.g.:
Suggested Domains
┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Domain        ┃ Status     ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ google.com    │ Registered │
│ gоogle.com    │ Available  │
└───────────────┴────────────┘




🎯 Future Goals and Improvements
Future versions of PhishiUrl aim to enhance functionality and introduce new features. Planned updates include:
Suggested Improvements

Optimize Website Cloning:
Integrate with goclone (https://github.com/goclone-dev/goclone) for faster and more accurate website cloning.
Fix issues with loading dynamic resources (e.g., external APIs).


Enhance Security:
Add detection for security headers (e.g., X-Frame-Options) to avoid detection by target sites.
Integrate with tools like Spoofy (https://github.com/MattKeeley/Spoofy) to analyze DNS and email vulnerabilities.


Advanced Reporting:
Generate visual reports (e.g., using Matplotlib) to display captured data.
Add statistical analysis (e.g., number of successful phishing attempts).



New Features

Iframe Mode Enhancements:
Add options to customize iframe appearance (e.g., fake headers, favicon).


Advanced Keylogger:
Capture real-time user input (keylogging) with an enable/disable option.


OSINT Integration:
Integrate with Telepathy (https://github.com/EmadYaY/Telepathy) to gather data from Telegram chats for phishing analysis.


Reverse Proxy Support:
Use a reverse proxy (e.g., with Nginx) to bypass iframe restrictions and improve site mimicry.



Integration with Other Tools

DLP Toolbox (https://dlptoolbox.com): To test and validate Data Loss Prevention (DLP) policies alongside phishing simulations.
Email Spoof Test (https://emailspooftest.com): To test organizational email security and simulate email phishing attacks.


🤝 Contributing
We welcome contributions! To report bugs, suggest new features, or submit a pull request:

Fork the repository: github.com/EmadYaY/PhishiUrl
Make your changes and submit a pull request.
For communication, use GitHub issues or contact the author via email (available on the GitHub profile).


📜 Version History

Version 1.2.8 (April 2025):
Added --download-all option to download all assets.
Added iframe mode with --use-iframe option.
Data capture only on form submission (reduced log size).
Improved handling of downloaded resource paths.


Previous Versions:
Version 1.2.7: Added initial cloning functionality and Ngrok integration.




📄 License
This project is licensed under the MIT License. See the LICENSE file for details.
