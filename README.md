![image-1](1.jpg "PhishiUrl")

# PhishiUrl

PhishiUrl is a powerful tool for generating and detecting Unicode-based homograph attacks. It is intended for use by cybersecurity professionals to identify potential phishing URLs by substituting characters in domain names with similar-looking Unicode counterparts.
a related article: [PDF](homograph_full.pdf "PhishiUrl")

## Description

PhishiUrl is designed to help identify and mitigate potential phishing attacks that exploit Unicode characters. These attacks can trick users by using domain names that look visually similar to legitimate ones but are, in fact, malicious. PhishiUrl generates these deceptive URLs, checks their availability, and tests their connection status, making it a valuable tool for cybersecurity analysis.

## Features

- **Generate Phishing URLs:** Generate potential phishing URLs by replacing characters in a domain with visually similar Unicode characters.
- **Check Domain Availability:** Verify whether the generated domains are available for registration.
- **Connection Status Check:** Test the connection status of the generated URLs to see if they are reachable.
- **Detailed Reporting:** Option to output results to a file for detailed analysis.

## Requirements

- Python 3.x
- Required Python libraries listed in `requirements.txt`.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/EmadYaY/PhishiUrl.git
    cd phishiurl
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage
### Basic Usage

Generate phishing URLs by substituting characters:

```bash
python3 phishiurl.py -url example.com -g
```

## Check Domain Availability
### Check if the generated domain names are available for registration:

```bash
python3 phishiurl.py -url example.com -g -a
```

## Check Connection Status
### Check the connection status of the generated URLs:

```bash
python3 phishiurl.py -url example.com -g -c
```

## Output to File
### Save the output of the analysis to a file:

```bash
python3 phishiurl.py -url example.com -g -o output.txt
```

## Full Report
### Generate a detailed report of the analysis:

```bash
python3 phishiurl.py -url example.com -g -r -o report.txt
```

## Examples
### Example 1: Generate evil URLs and check if they are reachable:

  ```bash
  python3 phishiurl.py -url testdomain.com -g -c
  ```
### Example 2: Check if the generated URLs are available for registration and save the results:

  ```bash
  python3 phishiurl.py -url testdomain.com -g -a -o availability.txt
  ```
----
## User Manual
### Introduction
PhishiUrl is a tool designed for generating and detecting Unicode-based homograph attacks. These attacks involve replacing characters in a domain name with visually similar characters from different Unicode sets, potentially deceiving users into visiting malicious websites. This manual will guide you through the installation and use of PhishiUrl.

Installation:
    Install These:
      1:
          ```
              pip install python-nmap 
          ```
      2:
          ```
              pip install python-whois 
          ```
       

  1. Clone the Repository:

        ```bash
            git clone https://github.com/EmadYaY/PhishiUrl.git
            cd PhishiUrl
        ```
    
  2. Install Dependencies:
        ```bash
            pip install -r requirements.txt
        ```

----
![image-1](2.jpg "PhishiUrl")


# Contributing:
Contributions are welcome! Please submit a pull request or report any issues.

# License:
This project is licensed under the  License - see the LICENSE file for details.

# Author:
Created by Emad | Fazel Mohammad Ali Pour.



# Copyright Notice: 

### © All rights reserved. Credits belong to the original programmer, Emad.





