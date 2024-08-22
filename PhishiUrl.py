#!/usr/bin/env python
import itertools
from platform import python_version
from sys import exit
from argparse import ArgumentParser
from nmap import PortScanner
from whois import whois
from os import system

# Tool and author information
TOOL_NAME = "PhishiUrl"
AUTHOR_NAME = "Emad"
VERSION_NUM = "0.0.1"
GITHUB_URL = "github.com/EmadYaY"

# Check Python version
if python_version().startswith('2'):
    print(f'You are using Python version {python_version()}\n'
          'Please, use Python version 3.X')
    exit(1)

# Terminal colors for output
RED, WHITE, GREEN, END, YELLOW = '\033[91m', '\33[97m', '\033[1;32m', '\033[0m', '\33[93m'

# Unicode mappings for character substitution
unicode_replacements = [{'a':'\u0430'}, {'c': '\u03F2'}, {'e': '\u0435'}, {'o': '\u043E'}, {'p': '\u0440'},
                        {'s': '\u0455'}, {'d': '\u0501'}, {'q': '\u051B'}, {'w': '\u051D'}]

# Additional Unicode mappings for Persian, Arabic, Kurdish, and Turkish
extra_unicode_replacements = [{'aleph':'\u0627'}, {'ae':'\u06D5'}, {'waw':'\u0648'}, {'pe':'\u067E'}, 
                              {'gaf':'\u06AF'}, {'dotless_i':'\u0131'}]

# Null character example
null_char = '\x00'

def display_banner(output=False):
    system('clear')
    banner = f'''
{GREEN}██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗██╗   ██╗██████╗ ██╗                   ██╗██████╗ ███╗   ██╗
{GREEN}██╔══██╗██║  ██║██║██╔════╝██║  ██║██║██║   ██║██╔══██╗██║                   ██║██╔══██╗████╗  ██║
{WHITE}██████╔╝███████║██║███████╗███████║██║██║   ██║██████╔╝██║         █████╗    ██║██║  ██║██╔██╗ ██║
{WHITE}██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║   ██║██╔══██╗██║         ╚════╝    ██║██║  ██║██║╚██╗██║
{RED}██║     ██║  ██║██║███████║██║  ██║██║╚██████╔╝██║  ██║███████╗              ██║██████╔╝██║ ╚████║
{RED}╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝              ╚═╝╚═════╝ ╚═╝  ╚═══╝
                                                                                                                                     

{GREEN}Tool: {TOOL_NAME}{END}
{GREEN}By: {AUTHOR_NAME}{END}
{WHITE}Version: {VERSION_NUM}{END}
{WHITE}GitHub: {GITHUB_URL}{END}\n'''
    print_output(banner, output)

def sanitize_text(text):
    for color in (RED, WHITE, GREEN, END, YELLOW):
        text = text.replace(color, '')
    return text

def clear_file(filepath):
    with open(filepath, 'w') as file:
        file.write('')

def check_domain_availability(domain_name):
    try:
        return whois(domain_name).registrar
    except:
        return None

def print_output(message, output_file=False):
    print(message)
    if output_file:
        with open(output_file, 'a') as file:
            file.write(sanitize_text(message) + '\n')

def display_original_url(original_url, check_connection, output_file):
    print_output(f'{GREEN}[~]{END} Original: {original_url}', output_file)
    if check_connection:
        print_output(test_connection(original_url), output_file)

def create_phishing_url(chars, unicode_chars, unicode_names, new_url, original_url, output_file):
    print_output(f'\n{GREEN}[*]{END} Original Domain: {original_url}\n'
                 f'{GREEN}[*]{END} Replaced Chars: {chars}\n'
                 f'{GREEN}[*]{END} Using Unicode: {unicode_chars}\n'
                 f'{GREEN}[*]{END} Unicode Names: {unicode_names}\n'
                 f'{RED}[*]{END} phishing URL: {new_url}', output_file)

def generate_phishing_urls(domain, tld, check_connection=False, output_file=False, check_availability=False):
    domain = domain.lower()
    phishing_replacements = unicode_replacements + extra_unicode_replacements
    matching_chars = [key for repl in phishing_replacements for key in repl if key in domain]

    for combination in itertools.chain.from_iterable(itertools.combinations(matching_chars, i) for i in range(1, 9)):
        new_domain = domain
        unicode_chars, char_names = [], []
        for char in combination:
            for repl in phishing_replacements:
                if char in repl:
                    unicode_char = repl[char]
                    unicode_chars.append(unicode_char)
                    new_domain = new_domain.replace(char, unicode_char)
                    for u_repl in unicode_replacements + extra_unicode_replacements:
                        if unicode_char in u_repl.values():
                            char_names.append(list(u_repl.keys())[0])
        create_phishing_url(combination, unicode_chars, char_names, new_domain + tld, domain, output_file)
        if check_connection:
            print_output(test_connection(new_domain + tld), output_file)
        if check_availability:
            availability_message = check_domain_availability(new_domain + tld)
            print_output(f'{GREEN}[*]{END} Available domain' if availability_message is None else f'{YELLOW}[!]{END} Unavailable domain', output_file)

        for path in generate_phishing_paths(new_domain, check_connection, output_file):
            print_output(detect_phishing_url(path), output_file)
            if check_connection:
                print_output(test_connection(path), output_file)

def generate_phishing_paths(base_url, check_connection=False, output_file=False):
    example_paths = ["/example", "/سلام", "/index", "/test"]
    phishing_paths = []
    for path in example_paths:
        for repl in extra_unicode_replacements + [{'null': null_char}]:
            original_char = list(repl.keys())[0]
            phishing_char = repl[original_char]
            if original_char in path:
                phishing_path = path.replace(original_char, phishing_char)
                phishing_paths.append(base_url + phishing_path)
    return phishing_paths

# -------------- BEGIN NETWORK MODULE ----------------- #
def test_connection(url):
    scanner = PortScanner()
    result = scanner.scan(url, arguments='-sn')
    uphosts = int(result['nmap']['scanstats']['uphosts'])
    return f'{GREEN}[*]{END} Connection test: UP' if uphosts > 0 else f'{YELLOW}[!]{END} Connection test: DOWN'

def detect_phishing_url(url):
    malicious_chars = [c for c in url if any(c in u_repl.values() for u_repl in unicode_replacements + extra_unicode_replacements)]
    return f'{GREEN}[*]{END} No phishing chars found' if not malicious_chars else f'{YELLOW}[!]{END} phishing Chars found: {", ".join(malicious_chars)}'
# -------------- END NETWORK MODULE ----------------- #

def main():
    parser = ArgumentParser(description=f'{TOOL_NAME} - Enhanced phishing URL Generator and Detector')
    parser.add_argument('-url', help='Domain name to analyze (e.g., example.com)', required=True)
    parser.add_argument('-g', '--generate', action='store_true', help='Generate phishing URLs')
    parser.add_argument('-c', '--check', action='store_true', help='Check domain connection status')
    parser.add_argument('-o', '--output', help='Output results to a file')
    parser.add_argument('-a', '--available', action='store_true', help='Check if domain is available')
    parser.add_argument('-r', '--report', action='store_true', help='Generate a detailed report')

    args = parser.parse_args()

    if args.output:
        clear_file(args.output)
        display_banner(args.output)
    else:
        display_banner()

    domain = args.url
    tld = ''.join(['.' + x for x in domain.split('.')[1:]])

    if args.generate:
        display_original_url(domain, args.check, args.output)
        generate_phishing_urls(domain.split('.')[0], tld, args.check, args.output, args.available)
    else:
        print_output(detect_phishing_url(domain), args.output)
        if args.check:
            print_output(test_connection(domain), args.output)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        exit()
