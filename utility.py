"""
Nom du fichier : env_binary.py
Auteur        : Targazh
Date          : 2025-02-01
Description   : Script de pré-analyze de binaire avant d'entamer le reverse (malware - ctf).
Github        : 
"""

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
    Checks if Address Space Layout Randomization (ASLR) is disabled on the system.

    ASLR is a security feature that randomizes the memory addresses used by system and application processes.
    This function reads the value from '/proc/sys/kernel/randomize_va_space' to determine if ASLR is disabled.

    Returns:
        bool: True if ASLR is disabled, False otherwise.
    """
    import os
    aslr_disabled = False
    if os.path.exists('/proc/sys/kernel/randomize_va_space'):
        with open('/proc/sys/kernel/randomize_va_space') as f:
            aslr_disabled = f.read().strip() == '0'
        if not aslr_disabled:
            user_input = input("L'ASLR est activé. Voulez-vous le désactiver ? (y/n) : ")
            if user_input.lower() == 'y' or user_input.lower() == '':
                os.system('echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null')
                aslr_disabled = True
    return aslr_disabled

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
    aslr_status = "ASLR désactivé : [bold red]Oui[/bold red] :warning:" if aslr_check else "ASLR désactivé : [bold green]Non[/bold green] :white_check_mark:"
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