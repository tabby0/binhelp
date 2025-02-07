"""
Nom du fichier : env_binary.py
Auteur        : Targazh
Date          : 2025-02-01
Description   : Script de pré-analyze de binaire avant d'entamer le reverse (malware - ctf).
Github        : 
"""

from parser_config import *
from analysis import *
from utility import *
from crypto_hash import sha256_file
from angr_utilities import *
from calling_convention import *
import angr

import os
import argparse
import re

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
# pip install --upgrade pip setuptools wheel
#install flare-floss
# isntall setuptools



console = Console(record=True)

""" def print_calling_convention(arch_name):

    if arch_name == "X86":
        user_input = input("Voulez-vous utiliser fastcall, cdecl ou stdcall ? (f/c/s): ").strip().lower()
        if user_input == 'f':
            console.print(Panel(f"{fastcall_calling_convention}", title="fastcall Calling Convention", subtitle="Details", expand=False))
        elif user_input == 'c':
            console.print(Panel(f"{cdecl_calling_convention}", title="cdecl Calling Convention", subtitle="Details", expand=False))
        elif user_input == 's':
            console.print(Panel(f"{stdcall_calling_convention}", title="stdcall Calling Convention", subtitle="Details", expand=False))
        else:
            print("Option non reconnue.")
    elif arch_name == "AMD64":
        console.print(Panel(f"{amd64_calling_convention}", title="AMD64 Calling Convention", subtitle="Details", expand=False))
    elif arch_name == "AARCH64":
        console.print(Panel(f"{arm64_calling_convention}", title="AARCH64 Calling Convention", subtitle="Details", expand=False))
    elif arch_name == "ARMEL":
        console.print(Panel(f"{arm32_calling_convention}", title="ARM Calling Convention", subtitle="Details", expand=False))
    else:
        print("Architecture non supportée, vous pouvez faire une issue pour demander le support.")
 """

def main():
    
    # rajouter une fonctionnalitée pour voir l'équivalent des fonction en python
    # stringsifter n'est pas encore compatible avec python 3.12 | à surveiller
    # Pour chaque vulnérabilité présentée mais un liens vers un write up ou un chall rootme pour travailler la vulnérabilité
    # Ajouter une license pour tout tes scripts
    # checker si tu as cette implémentation dans ton script en python
    # Ajouter les licenses etc ...
    # Ajouter un graph du CFG
    # Ajouter une detection des fonctions les plus vulnérables
    # Ajoutes une liste des principaux types avec leurs valeurs dans IDA
    # Ajoute les principaux raccourcis de IDA
    # ajoute pour chaque architecture les principales mnémoniques à connaitre avant de reverse avec un example et une description en français
    # playwrihgt pour scrapper un site internet

    ### Variables du main ### 
    html_content = ""
    parser_config_dicts = [
        all_libsodium_functions,
        all_c_file_manipulation,
        all_process_manipulation_functions,
        all_network_functions,
        all_windows_encryption_functions,
        all_memory_access_functions,
        all_certificate_management_functions,
        all_random_number_generation_functions,
        all_hash_generation_functions,
        all_other_syscal,
        all_openssl_functions,
        all_type_conversion_functions,
        all_terminal_functions

    ]
    parser_config_dic_info = [
        all_libsodium_functions_infos,
        all_c_file_manipulation_infos,
        all_process_manipulation_functions_infos,
        all_network_functions_infos,
        all_windows_encryption_functions_infos,
        all_memory_access_functions_infos,
        all_certificate_management_functions_infos,
        all_random_number_generation_functions_infos,
        all_hash_generation_functions_infos,
        all_other_syscal_infos,
        all_openssl_functions_infos,
        all_type_conversion_functions_infos,
        all_terminal_functions_infos
    ]

    regex_dic = {
        'Adresses IP': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'),
        'Noms de domaine': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
        'Chemins de fichiers': re.compile(r'(?:[a-zA-Z]:\\|\\\\[^\\]+\\|/)(?:[^\\/:*?"<>|\r\n]+[\\/])*[^\\/:*?"<>|\r\n]*'),
        'Hachages SHA-1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'Hachages SHA-256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'Hachages MD5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'Hachages SHA-512': re.compile(r'\b[a-fA-F0-9]{128}\b'),
        'Hachages bcrypt': re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),
        'Hachages SHA-3-256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'Hachages SHA-3-512': re.compile(r'\b[a-fA-F0-9]{128}\b'),
        'Adresses email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'Flag': re.compile(r'\b[A-Za-z0-9]+\{[^}]+\}'),
        'Noms de fichiers': re.compile(r'\b\w+\.(?:bin|exe|ps1|batch|sh|pdf|docx|zip|tar|tar\.gz|7z|rar|gz|png|jpg|jpeg|txt|log|iso|dmg|pkg|deb|rpm|apk|msi|py|js|html|css|json|xml|sql|db|bak|conf|ini|yml|yaml|md)\b', re.IGNORECASE),
    }

    ### HELPER BANNER ###
    parser = argparse.ArgumentParser(description="Script de pré-analyze de binaire avant d'entamer le reverse (malware - ctf).")
    parser.add_argument("binary", help="Le chemin vers le fichier binaire à analyser")
    args = parser.parse_args()

    ### WELCOME BANNER ###
    banner_text = Text("Binhelp - framework, en français 🇫🇷 , pour aider les débutants en RE (CTF et/ou malware)", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
    console.print(banner_panel)

    ### AVERTISSMENT UTILISATEUR ###
   
    print_user_info(console, check_internet(), check_vm(), check_aslr(), os.uname())

    user_input = input("Voulez-vous continuer l'analyse ? (y/n): ").strip().lower()
    if user_input != 'y' and user_input != '':
        print("Analyse terminée.")
        return
    
    ### ANALYSE DU BINAIRE AVEC ANGR ###
    proj = angr.Project(args.binary,auto_load_libs=False)
    arch = proj.arch
    entry_point = hex(proj.entry)
    filename = proj.filename
    file_path = proj.loader._main_binary_path
    min_load_addr = hex(proj.loader.min_addr)
    max_load_addr = hex(proj.loader.max_addr)
    shared_libraries = proj.loader.shared_objects
    sha256sum = sha256_file(proj.loader._main_binary_path)
    is_stack_executable = proj.loader.main_object.execstack
    is_position_independent = proj.loader.main_object.pic
    binary_strings = extract_strings(proj)

    ### AFFICHAGE DES DONNEES ANALYSEES AVEC ANGR ###
    console.print(Panel(f"[bold red][-] Architecture:[/bold red] [blue]{arch}[/blue]\n"
                        f"[bold red][-] Point d'entrée:[/bold red] [bold]{entry_point}[/bold]\n"
                        f"[bold red][-] Nom du fichier:[/bold red] [bold]{filename}[/bold]\n"
                        f"[bold red][-] Chemin du fichier:[/bold red] [bold]{file_path}[/bold]\n"
                        f"[bold red][-] Adresse de chargement minimale:[/bold red] [bold]{min_load_addr}[/bold]\n"
                        f"[bold red][-] Adresse de chargement maximale:[/bold red] [bold]{max_load_addr}[/bold]\n"
                        f"[bold red][-] Bibliothèques partagées:[/bold red] [bold]{shared_libraries}[/bold]\n"
                        f"[bold red][-] SHA-256:[/bold red] [bold green]{sha256sum}[/bold green]\n"
                        f"[bold red][-] Pile exécutable:[/bold red] [bold red]{is_stack_executable}[/bold red]\n"
                        f"[bold red][-] Position indépendante:[/bold red] [bold red]{is_position_independent}[/bold red]",
                        title="Binary Information", subtitle="Details", expand=False))

    banner_text = Text(f"Calling convention possible pour {arch}", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
    console.print(banner_panel)

    ### AFFICHAGE DE LA CONVENTION D'APPEL ###
    console.print("Note: Un petit check manuel sur les conventions d'appel est souhaitable. 🔍\n")
   
    display_calling_convention(console, arch.name)

    ### AFFICHAGE DU CFG ###
    try:
        with console.status("[bold blue]Génération du CFG...[/bold blue]", spinner="dots"):
            cfg = proj.analyses.CFGFast()
            console.print(f"CFG généré avec {len(cfg.graph.nodes)} noeuds et {len(cfg.graph.edges)} arêtes.")
            
    except Exception as e:
        console.print(f"Erreur lors de la génération du CFG: {e}")

    banner_text = Text("Affichage des fonctions identifiées", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
    console.print(banner_panel)
    console.print("Note: Un petit check manuel sur les imports (dans IDA/Ghidra) est conseillé 🔍\n")
    for functions_dict in parser_config_dicts:
        
        analyze_functions(cfg, console, functions_dict)
    
    user_input = input("Voulez-vous les renseignements détaillés des fonctions ? (y/n): ").strip().lower()

    if user_input == 'y' or user_input == '':
        banner_text = Text("Affichage détaillée des fonctions identifiées", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
        console.print(banner_panel)
        for functions_dict in parser_config_dic_info:
            analyze_functions(cfg, console, functions_dict)

    user_input = input("Voulez-vous exécuter la portion de code sur YARA ? (y/n): ").strip().lower()
    
    if user_input == 'y' or user_input == '':
        banner_text = Text("Affichage des régles  Yara", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
        console.print(banner_panel)
        yara_rules_dir = ".yara_rules"
        
        if check_internet():
                user_input = input("Une connexion Internet a été détectée. Voulez-vous télécharger les règles YARA ? (y/n): ").strip().lower()
                try:
                    if not os.path.exists(yara_rules_dir):
                        os.makedirs(yara_rules_dir)
                except Exception as e:
                    pass
                if user_input == 'y' or user_input == '':
                    for name, url in yara_rules_list.items():
                        local_filename = os.path.join(yara_rules_dir, f"{name}.yar")
                        download_file(url, local_filename)
                        print(f"\nNom de la règle: {name}")
                        find_yara_matches(console,local_filename, file_path)
                else:
                    print("Téléchargement des règles YARA ignoré. Exécution uniquement des règles locales.")
                    if not os.path.exists(yara_rules_dir):
                        os.makedirs(console,yara_rules_dir)
                    yara_files = [f for f in os.listdir(yara_rules_dir) if f.endswith(('.yar', '.rules', '.rule', '.yara'))]
                    if not yara_files:
                            print("Le répertoire .yara_rules est vide. Aucune règle YARA locale à exécuter.")
                    else:
                            for local_rule in yara_files:
                                local_filename = os.path.join(yara_rules_dir, local_rule)
                                print(f"\nNom de la règle: {local_rule}")
                                find_yara_matches(console,local_filename, file_path)
        
        else:
                print("Pas de connexion Internet détectée. Exécution uniquement des règles locales.")

    banner_text = Text("Affichage des strings identifiées par les regex", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
    console.print(banner_panel)
    console.print("Note: Vous pouvez également utiliser les commandes strings ou floss en association avec grep. 🔍\n")
    

    # Utiliser floss pour extraire les chaînes si le binaire est un exécutable Windows
    if proj.loader.main_object.os == 'windows':
        
        banner_text = Text("Binaire Windows 🪟 détecté. Utilisation de FLOSS de Mandiant pour extraire les chaînes de la stack.", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold blue")
        console.print(banner_panel)
        try:
            with console.status("[bold bleue]Analyse en cours...[/bold bleue]", spinner="dots"):
                cfg = proj.analyses.CFGFast(resolve_indirect_jumps=False, force_complete_scan=False)
        except Exception as e:
            print(f"Erreur lors de la création du CFG: {e}")
            return
        floss_strings = extract_strings_with_floss(file_path)
        console.print(f"Extracted {len(floss_strings)} strings using FLOSS.")
        binary_strings.extend(floss_strings)

    regex_matches = find_regex_matches(binary_strings, regex_dic)
    for label, matched_strings in regex_matches.items():
        table = Table(title=f"[bold white]{label} (possiblement) [/bold white]", show_header=True, header_style="bold white")
        table.add_column("Correspondances", style="bold white")
        for matched_string in matched_strings:
            colored_string = Text(matched_string, style="bold green")
            table.add_row(colored_string)
        if table.row_count > 0:
            console.print(table)
            console.print('\n')
        else:
            console.print('Aucune correspondance trouvée.\n')


    # Reactivate ASLR if it was disabled
    if not check_aslr():
        user_input = input("L'ASLR est désactivé. Voulez-vous le réactiver ? (y/n): ").strip().lower()
        if user_input == 'y' or user_input == '':
            try:
                set_aslr(2)
                console.print("[bold green]L'ASLR a été réactivé avec succès.[/bold green]")
            except Exception as e:
                console.print(f"[bold red]Erreur lors de la réactivation de l'ASLR: {e}[/bold red]")
        else:
            console.print("[bold yellow]L'ASLR reste désactivé.[/bold yellow]")
    html_content += console.export_html(inline_styles=True)
    save_to_html(html_content)


if __name__ == "__main__":
    main()