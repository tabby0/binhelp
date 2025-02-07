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
    table = Table(title="Extracted Strings")

    table.add_column("Strings", style="cyan")
    table.add_column("Encoding", style="magenta")
    table.add_column("Offset", style="green")

    for s in strings:
        table.add_row(s.string, s.encoding.name, f"0x{s.offset:x}")

    console.print(table)

def display_strings_stringsifter(strings: List[StaticString],console):
    """
    Display the extracted strings in a formatted table using Rich.

    :param strings: A list of StaticString objects.
    :type strings: List[StaticString]
    """
    
    table = Table(title="Extracted Strings")

    table.add_column("Strings", style="cyan")
    table.add_column("Encoding", style="magenta")
    table.add_column("Offset", style="green")

    featurizer = Featurizer()

    
    features = [
        ('has_ip', 'IP Address'),
        ('has_ip_srv', 'IP Server'),
        ('has_url', 'URL'),
        ('has_email', 'Email Address'),
        ('has_fqdn', 'FQDN'),
        ('has_namespace', 'Namespace'),
        ('has_msword_version', 'MS Word Version'),
        ('has_packer', 'Packer'),
        ('has_crypto_related', 'Crypto Related'),
        ('has_privilege_constant', 'Privilege Constant'),
        ('has_mozilla_api', 'Mozilla API'),
        ('is_strict_fqdn', 'Strict FQDN'),
        ('has_hive_name', 'Hive Name'),
        ('is_mac', 'MAC Address'),
        ('has_extension', 'Extension'),
        ('is_md5', 'MD5'),
        ('is_sha1', 'SHA1'),
        ('is_sha256', 'SHA256'),
        ('has_guid', 'GUID'),
        ('is_antivirus', 'Antivirus'),
        ('is_common_dll', 'Common DLL'),
        ('is_boost_lib', 'Boost Library'),
        ('is_delphi_lib', 'Delphi Library'),
        ('has_event', 'Event'),
        ('is_registry', 'Registry'),
        ('has_malware_identifier', 'Malware Identifier'),
        ('has_sid', 'SID'),
        ('has_keylogger', 'Keylogger'),
        ('has_oid', 'OID'),
        ('has_product_id', 'Product ID'),
        ('is_oss', 'OSS'),
        ('is_user_agent', 'User Agent'),
        ('has_sddl', 'SDDL'),
        ('has_protocol', 'Protocol'),
        ('is_protocol_method', 'Protocol Method'),
        ('is_base64', 'Base64'),
        ('is_hex_not_numeric_not_alpha', 'Hex Not Numeric Not Alpha'),
        ('has_format_specifier', 'Format Specifier'),
        ('ends_with_line_feed', 'Ends with Line Feed'),
        ('has_path', 'Path'),
        ('has_pdb', 'PDB'),
        ('has_privilege', 'Privilege'),
        ('is_cpp_runtime', 'C++ Runtime'),
        ('is_library', 'Library'),
        ('is_date', 'Date'),
        ('is_pe_artifact', 'PE Artifact'),
        ('has_public_key', 'Public Key'),
        ('is_code_page', 'Code Page'),
        ('is_language', 'Language'),
        ('is_region_tag', 'Region Tag'),
        ('has_not_latin', 'Not Latin'),
        ('is_malware_api', 'Malware API'),
        ('is_environment_variable', 'Environment Variable'),
        ('has_variable_name', 'Variable Name'),
    ]

    for feature, description in features:
        table = Table()
        table.add_column("String", style="blue")
        table.add_column("Encoding", style="white")
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

def extract_strings_with_floss(file_path):
    import subprocess
    result = subprocess.run(['floss', file_path], capture_output=True, text=True)
    return [line.encode('ascii', errors='ignore') for line in result.stdout.splitlines()]

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

def check_aslr():
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
            user_input = input("L'ASLR est désactivé. Voulez-vous l'activer ? (y/n) : ")
            if user_input.lower() == 'y' or user_input.lower() == '':
                if os.system('echo 2 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null') == 0:
                    print("ASLR activé avec succès ✅")
                    return True
                
                else:
                    print("Échec de l'activation de l'ASLR ❌")
                    return True
        else:
            user_input = input("L'ASLR est activé. Voulez-vous le désactiver ? (y/n) : ")
            if user_input.lower() == 'y' or user_input.lower() == '':
                if os.system('echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null') == 0:
                    print("ASLR désactivé avec succès ✅")
                   
                    return False
                else:
                    print("Échec de la désactivation de l'ASLR ❌")
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
    internet_status = "Connexion Internet active : [bold red]Oui[/bold red] :warning:" if internet_connection else "Connexion Internet active : [bold green]Non[/bold green] :white_check_mark:"
    vm_status = "Exécution dans une VM : [bold red]Oui[/bold red] :warning:" if vm_check else "Exécution dans une VM : [bold green]Non[/bold green] :white_check_mark:"
    aslr_status = "ASLR désactivé : [bold red]Oui[/bold red] :warning:" if not aslr_check else "ASLR désactivé : [bold green]Non[/bold green] :white_check_mark:"
    system_info_panel = Panel(
        f"[bold red][-] Système d'exploitation :[/bold red] [blue]{os_info.sysname} {os_info.release}[/blue]\n"
        f"{internet_status}\n"
        f"{vm_status}\n"
        f"{aslr_status}",
        title="Informations Système", subtitle="Détails", expand=False, border_style="bold blue"
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

def find_yara_matches(console,yara_file, file):
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
    import os
    rules = yara.compile(filepath=yara_file)
    matches = rules.match(file)
    
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Match", style="green")

    if matches:
        for match in matches:
            table.add_row(str(match))
    else:
        table.add_row("[red]Pas de match[/red]")

    console.print(table)