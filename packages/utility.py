"""
Nom du fichier : env_binary.py
Auteur        : Targazh
Date          : 2025-02-01
Description   : Script de pré-analyze de binaire avant d'entamer le reverse (malware - ctf).
Github        : 
"""
import re
from typing import List
from itertools import chain
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from preprocess import Featurizer
from floss.results import StaticString, StringEncoding
# Copyright 2017 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# we don't include \r and \n to make output easier to understand by humans and to simplify rendering
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_4 = re.compile(rb"([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
MIN_LENGTH = 4
SLICE_SIZE = 4096


def display_strings(strings: List[StaticString], console: Console):
    """
    Display the extracted strings in a formatted table using Rich.

    :param strings: A list of StaticString objects.
    :type strings: List[StaticString]
    """
    table = Table(title="[bold]Extracted Strings[/bold] 📝")

    table.add_column("Strings", style="blue")
    table.add_column("Encoding")
    table.add_column("Offset", style="red")

    for s in strings:
        table.add_row(s.string, s.encoding.name, f"0x{s.offset:x}")

    console.print(table)

def display_strings_stringsifter(strings: List[StaticString],console):
    """
    Display the extracted strings in a formatted table using Rich.

    :param strings: A list of StaticString objects.
    :type strings: List[StaticString]
    """
    
    table = Table(title="[bold]Extracted Strings[/bold] 📝")


    featurizer = Featurizer()

    
    features = [
        ('has_ip', '[bold]IP Address[/bold] 🌐'),
        ('has_ip_srv', '[bold]IP Server[/bold] 🖥️'),
        ('has_url', '[bold]URL[/bold] 🔗'),
        ('has_email', '[bold]Email Address[/bold] 📧'),
        ('has_fqdn', '[bold]FQDN[/bold] 🌍'),
        ('has_namespace', '[bold]Namespace[/bold] 📂'),
        ('has_msword_version', '[bold]MS Word Version[/bold] 📄'),
        ('has_packer', '[bold]Packer[/bold] 📦'),
        ('has_crypto_related', '[bold]Crypto Related[/bold] 🔒'),
        ('has_privilege_constant', '[bold]Privilege Constant[/bold] 🔑'),
        ('has_mozilla_api', '[bold]Mozilla API[/bold] 🦊'),
        ('is_strict_fqdn', '[bold]Strict FQDN[/bold] 🌐'),
        ('has_hive_name', '[bold]Hive Name[/bold] 🐝'),
        ('is_mac', '[bold]MAC Address[/bold] 💻'),
        ('has_extension', '[bold]Extension[/bold] 📎'),
        ('is_md5', '[bold]MD5[/bold] 🔑'),
        ('is_sha1', '[bold]SHA1[/bold] 🔑'),
        ('is_sha256', '[bold]SHA256[/bold] 🔑'),
        ('has_guid', '[bold]GUID[/bold] 🆔'),
        ('is_antivirus', '[bold]Antivirus[/bold] 🛡️'),
        ('has_event', '[bold]Event[/bold] 📅'),
        ('is_registry', '[bold]Registry[/bold] 🗄️'),
        ('has_malware_identifier', '[bold]Malware Identifier[/bold] 🐛'),
        ('has_sid', '[bold]SID[/bold] 🆔'),
        ('has_keylogger', '[bold]Keylogger[/bold] ⌨️'),
        ('has_oid', '[bold]OID[/bold] 🆔'),
        ('has_product_id', '[bold]Product ID[/bold] 🆔'),
        ('is_oss', '[bold]OSS[/bold] 🖥️'),
        ('is_user_agent', '[bold]User Agent[/bold] 🕵️'),
        ('has_sddl', '[bold]SDDL[/bold] 📜'),
        ('has_protocol', '[bold]Protocol[/bold] 📡'),
        ('is_protocol_method', '[bold]Protocol Method[/bold] 📡'),
        ('is_base64', '[bold]Base64[/bold] 🔢'),
        ('is_hex_not_numeric_not_alpha', '[bold]Hex Not Numeric Not Alpha[/bold] 🔢'),
        ('has_format_specifier', '[bold]Format Specifier[/bold] 🔤'),
        ('ends_with_line_feed', '[bold]Ends with Line Feed[/bold] ↩️'),
        ('has_path', '[bold]Path[/bold] 📁'),
        ('has_pdb', '[bold]PDB[/bold] 📄'),
        ('has_privilege', '[bold]Privilege[/bold] 🔑'),
        ('is_date', '[bold]Date[/bold] 📅'),
        ('has_public_key', '[bold]Public Key[/bold] 🔑'),
        ('is_code_page', '[bold]Code Page[/bold] 📄'),
        ('is_language', '[bold]Language[/bold] 🈯'),
        ('is_region_tag', '[bold]Region Tag[/bold] 🏳️'),
        ('has_not_latin', '[bold]Not Latin[/bold] 🌐'),
        ('is_malware_api', '[bold]Malware API[/bold] 🐛'),
        ('has_variable_name', '[bold]Variable Name[/bold] 🔤'),
    ]

    for feature, description in features:
        table = Table()
        table.add_column("String", style="blue")
        table.add_column("Encoding")
        table.add_column("Offset", style="red")

        for s in strings:
            if getattr(featurizer, feature)(s.string) == 1:
                table.add_row(s.string, s.encoding.name, f"0x{s.offset:x}")

        if table.row_count > 0:
            panel = Panel(table, title=f"{description}", border_style="bold blue")
            console.print(panel)

def buf_filled_with(buf, character):
    dupe_chunk = character * SLICE_SIZE
    for offset in range(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset : offset + SLICE_SIZE]
        if dupe_chunk[: len(new_chunk)] != new_chunk:
            return False
    return True

def extract_ascii_strings(buf, n=MIN_LENGTH) -> List[StaticString]:
    """
    Extract ASCII strings from the given binary data.

    :param buf: A bytestring.
    :type buf: bytes
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: List[StaticString]
    """

    if not buf:
        return []

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return []

    r = None
    if n == 4:
        r = ASCII_RE_4
    else:
        reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    return [StaticString(string=match.group().decode("ascii"), offset=match.start(), encoding=StringEncoding.ASCII) for match in r.finditer(buf)]

def extract_unicode_strings(buf, n=MIN_LENGTH) -> List[StaticString]:
    """
    Extract naive UTF-16 strings from the given binary data.

    :param buf: A bytestring.
    :type buf: bytes
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: List[StaticString]
    """

    if not buf:
        return []

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return []

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    strings = []
    for match in r.finditer(buf):
        try:
            strings.append(StaticString(
                string=match.group().decode("utf-16"), offset=match.start(), encoding=StringEncoding.UTF16LE
            ))
        except UnicodeDecodeError:
            pass
    return strings

def extract_ascii_unicode_strings(binary_path, n=MIN_LENGTH) -> List[StaticString]:
    """
    Extract both ASCII and Unicode strings from the given binary data.

    :param binary_path: The path to the binary file.
    :type binary_path: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: List[StaticString]
    """
    with open(binary_path, "rb") as f:
        buf = f.read()
    
    # Extract strings from the buffer
    return list(chain(extract_ascii_strings(buf, n), extract_unicode_strings(buf, n)))


def extract_strings_with_floss(file_path, console):
    import subprocess
    result = subprocess.run(['floss', '--only', 'stack', 'tight', 'decoded', '--', file_path], capture_output=True, text=True, check=True)
    output = result.stdout.splitlines()
    
    # Filter out empty lines and create sections for different string types
    sections = {
        "FLOSS STACK STRINGS": [],
        "FLOSS TIGHT STRINGS": [],
        "FLOSS DECODED STRINGS": []
    }
    current_section = None

    for line in output:
        if "FLOSS STACK STRINGS" in line:
            current_section = "FLOSS STACK STRINGS"
        elif "FLOSS TIGHT STRINGS" in line:
            current_section = "FLOSS TIGHT STRINGS"
        elif "FLOSS DECODED STRINGS" in line:
            current_section = "FLOSS DECODED STRINGS"
        elif current_section and line.strip():
            sections[current_section].append(line.strip())

    # Create panels for each section
    panels = []
    for title, strings in sections.items():
        if strings:
            panel = Panel("\n".join(strings), title=title, border_style="bold blue")
            panels.append(panel)

    # Display all panels
    for panel in panels:
        console.print(panel)
    console.print(panel)
    return output

def download_file(url, local_filename):
    """
    Downloads a file from the given URL and saves it to the specified local filename.

    Args:
        url (str): The URL of the file to download.
        local_filename (str): The local path where the downloaded file will be saved.

    Raises:
        requests.exceptions.RequestException: If there is an issue with the HTTP request.
    """
    import requests
    with requests.get(url, stream=True) as request:
        request.raise_for_status()
        with open(local_filename, 'wb') as file:
            for chunk in request.iter_content(chunk_size=8192):
                file.write(chunk)

def check_internet():
    """
    Checks if the internet connection is available by attempting to reach Google.

    Returns:
        bool: True if the internet connection is available, False otherwise.
    """
    import requests

    try:
        requests.get("https://google.com")
        return True
    except requests.exceptions.RequestException:
        return False
    
def check_vm():
    """
    Checks if the current machine is running inside a virtual machine.

    This function reads the contents of '/proc/cpuinfo' and looks for specific terms
    that are commonly associated with virtual machines, such as 'hypervisor', 'vmware',
    and 'virtualbox'. If any of these terms are found, it returns True, indicating that
    the machine is likely a virtual machine. Otherwise, it returns False.

    Returns:
        bool: True if the machine is running inside a virtual machine, False otherwise.
    """
    return any(term in open('/proc/cpuinfo').read() for term in ['hypervisor', 'vmware', 'virtualbox'])

def check_aslr(console):
    """
    Checks the status of Address Space Layout Randomization (ASLR) on the system.

    ASLR is a security feature that randomizes the memory addresses used by system and application processes.
    This function reads the value from '/proc/sys/kernel/randomize_va_space' to determine the ASLR status and
    prompts the user to change it if desired.

    Returns:
        bool: True if ASLR is enabled, False otherwise.
    """
    import os
    aslr_status = None
    if os.path.exists('/proc/sys/kernel/randomize_va_space'):
        with open('/proc/sys/kernel/randomize_va_space') as f:
            aslr_status = f.read().strip()
        
        if aslr_status == '0':
            user_input = console.input("\n❓[bold] L'ASLR est désactivé. Voulez-vous l'activer ? (y/n) : [/bold]")
            console.print("\n")
            if user_input.lower() == 'y' or user_input.lower() == '':
                if os.system('echo 2 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null') == 0:
     
                    console.print("\nASLR activé avec succès ✅\n")
                    console.print("\n")
                    return True
                
                else:
                   
                    console.print("Échec de l'activation de l'ASLR ❌\n")
                    console.print("\n")
                    return True
        else:
            user_input = console.input("\n❓[bold] L'ASLR est activé. Voulez-vous le désactiver ? (y/n) : [/bold]")
            console.print("\n")
            if user_input.lower() == 'y' or user_input.lower() == '':
                if os.system('echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null') == 0:
                 
                    console.print("\nASLR désactivé avec succès ✅\n")
                    console.print("\n")
                    return False
                else:
                    
                    console.print("Échec de la désactivation de l'ASLR ❌\n")
                    console.print("\n")
                    return True
    
    

def set_aslr(state):
    import os
    """
        Sets the state of Address Space Layout Randomization (ASLR) on the system.

        This function attempts to set ASLR by writing the given state to '/proc/sys/kernel/randomize_va_space'.
        It uses a try-except block to handle any potential errors that may occur during this process.

        Args:
            state (int): The state to set ASLR to. Use 0 to disable and 2 to enable.

        Returns:
            bool: True if ASLR was successfully set, False otherwise.
    """
    try:
        os.system(f'echo {state} | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null')
        return True
    except Exception as e:
        print(f"Erreur lors de la modification de l'état de l'ASLR: {e}")
        return False

def print_user_info(console, internet_connection, vm_check, aslr_check, os_info):
    """
    Prints user system information to the console using the rich library.

    Args:
        console (Console): The rich console object to print the information.
        internet_connection (bool): True if there is an active internet connection, False otherwise.
        vm_check (bool): True if the system is running inside a virtual machine, False otherwise.
        aslr_check (bool): True if Address Space Layout Randomization (ASLR) is disabled, False otherwise.
        os_info (os.uname_result): An object containing information about the operating system.

    Returns:
        None
    """
    from rich.panel import Panel
    internet_status = "[bold]Connexion Internet active[/bold] : [bold red]Oui[/bold red] :warning:" if internet_connection else "[bold]Connexion Internet active[/bold]: [bold green]Non[/bold green] :white_check_mark:"
    vm_status = "[bold]Exécution dans une VM [/bold]: [bold red]Oui[/bold red] :warning:" if vm_check else "[bold]Exécution dans une VM [/bold] : [bold green]Non[/bold green] :white_check_mark:"
    aslr_status = "[bold]ASLR désactivée [/bold]: [bold red]Oui[/bold red] :warning:" if not aslr_check else "[bold]ASLR désactivé [/bold] : [bold green]Non[/bold green] :white_check_mark:"
    system_info_panel = Panel(
        f"[bold red][-] Système d'exploitation :[/bold red] [blue]{os_info.sysname} {os_info.release}[/blue]\n"
        f"{internet_status}\n"
        f"{vm_status}\n"
        f"{aslr_status}",
        title="Informations Système", expand=False, border_style="bold blue"
    )
    console.print(system_info_panel)

def find_regex_matches(strings, regex_dic):
    """
    Finds and returns matches of given regular expressions in a list of byte strings.
    Args:
        strings (list of bytes): A list of byte strings to search for matches.
        regex_dic (dict): A dictionary where keys are labels (str) and values are compiled regular expression patterns (re.Pattern).
    Returns:
        dict: A dictionary where keys are labels (str) and values are lists of decoded strings (str) that match the corresponding regular expression.
    """
    from collections import defaultdict
    
    matches = defaultdict(list)
    for s in strings:
        decoded_string = s.decode('ascii', errors='ignore')
        for label, pattern in regex_dic.items():
            if pattern.search(decoded_string):
                matches[label].append(decoded_string)
    return matches


def save_to_html(content, filename="binhelp_export.html"):
    """
    Save the given content to an HTML file.

    Args:
        content (str): The HTML content to be saved.
        filename (str, optional): The name of the file to save the content to. Defaults to "binhelp_export.html".

    Returns:
        None
    """
    with open(filename, "w") as f:
        f.write(content)

def find_yara_matches(console,yara_file, file,local_rule):
    """
    Finds and prints matches of a YARA rule in a given file.
    Args:
        console (Console): The rich console object to print the information.
        yara_file (str): The path to the YARA rule file.
        file (bytes): The content of the file to search for matches.
    Returns:
        None
    """
    import yara
    from rich.table import Table

    rules = yara.compile(filepath=yara_file)
    matches = rules.match(file)
    
    for match in matches:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Match", style="green")
        table.add_row(str(match))
        panel = Panel(table, title=f"{local_rule}", border_style="bold blue")
        console.print(panel)

    if not matches:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Match", style="green")
        table.add_row("[red]Pas de match[/red]")
        panel = Panel(table, title=f"{local_rule}", border_style="bold blue")
        console.print(panel)

def compute_imphash(binary_path):
    import pefile
    import subprocess
    """
    Compute the Import Hash (Imphash) of the given binary file.

    :param binary_path: The path to the binary file.
    :type binary_path: str
    :return: The computed Imphash value.
    :rtype: str
    """
    try:
        pe = pefile.PE(binary_path)
        return pe.get_imphash()
    except Exception:
        return "Neant"