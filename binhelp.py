"""
Nom du fichier : env_binary.py
Auteur        : Targazh
Date          : 2025-02-01
Description   : Script de pré-analyze de binaire avant d'entamer le reverse (malware - ctf).
Github        : 
"""

from packages.parser_config import *
from packages.analysis import *
from packages.utility import *
from packages.crypto_hash import sha256_file
from packages.angr_utilities import *
from packages.calling_convention import *

import angr
import os
import argparse
import re

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


console = Console(record=True)

def main():
    
    # rajouter une fonctionnalitée pour voir l'équivalent des fonction en python
    # Ajouter une license pour tout tes scripts
    # checker si tu as cette implémentation dans ton script en python
    # Ajouter les licenses etc ...
    # Ajouter un graph du CFG
    # Ajouter une detection des fonctions les plus vulnérables
    # Ajoutes une liste des principaux types avec leurs valeurs dans IDA
    # ajoute pour chaque architecture les principales mnémoniques à connaitre avant de reverse avec un example et une description en français


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
    console.print("\n")
    banner_text = Text("Binhelp - framework, en français 🇫🇷 , pour aider les débutants en RE (CTF et/ou malware)", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
    console.print(banner_panel,justify="center")

    ### AVERTISSMENT UTILISATEUR ###
    console.print("\n")
    print_user_info(console, check_internet(), check_vm(), check_aslr(console), os.uname())

    user_input = console.input("\n❓ [bold]Voulez-vous continuer l'analyse ? (y/n):[/bold] ").strip().lower()
    console.print("\n")
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
    binary_strings = extract_ascii_unicode_strings(file_path)

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
                        title="Binary Information", expand=False, border_style="bold blue"))

    banner_text = Text(f"Calling convention possible pour {arch}", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
    console.print(banner_panel,justify="center")

    ### AFFICHAGE DE LA CONVENTION D'APPEL ###
    console.print("\n[bold]💡 Note: Un petit check manuel sur les conventions d'appel est souhaitable.[/bold] 🔍\n", justify="center")
   
    display_calling_convention(console, arch.name)

    ### AFFICHAGE DU CFG ###
    try:
        with console.status("[bold blue]\nGénération du CFG...[/bold blue]", spinner="dots"):
            cfg = proj.analyses.CFGFast()
            console.print(f"\nCFG généré avec {len(cfg.graph.nodes)} noeuds et {len(cfg.graph.edges)} arêtes.")
            
    except Exception as e:
        console.print(f"\nErreur lors de la génération du CFG: {e}")
    console.print("\n")
    banner_text = Text("🕵️ Affichage des fonctions identifiées ", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
    console.print(banner_panel,justify="center")
    console.print("\n[bold]💡Note: Un petit check manuel sur les imports (dans IDA/Ghidra) est conseillé [/bold] 🔍\n", justify="center")
    for functions_dict in parser_config_dicts:
        
        analyze_functions(cfg, console, functions_dict)
    
    user_input = console.input("\n[bold]❓ Voulez-vous les renseignements détaillés des fonctions ? (y/n):[/bold] ").strip().lower()
    console.print("\n")
    if user_input == 'y' or user_input == '':
        banner_text = Text("Affichage détaillée des fonctions identifiées", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
        console.print(banner_panel,justify="center")
        for functions_dict in parser_config_dic_info:
            analyze_functions(cfg, console, functions_dict)

    user_input = console.input("\n[bold]❓ Voulez-vous exécuter la portion de code sur YARA ? (y/n):[/bold] ").strip().lower()
    console.print("\n")
    if user_input == 'y' or user_input == '':
        banner_text = Text("Affichage des régles  Yara", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
        console.print(banner_panel,justify="center")
        yara_rules_dir = ".yara_rules"
        
        if check_internet():
                user_input = console.input("\n🌐 [bold]Une connexion Internet a été détectée. Voulez-vous télécharger les règles YARA ? (y/n):[/bold] ").strip().lower()
                console.print("\n")
                try:
                    if not os.path.exists(yara_rules_dir):
                        os.makedirs(yara_rules_dir)
                except Exception as e:
                    pass
                if user_input == 'y' or user_input == '':
                    for name, url in yara_rules_list.items():
                        local_filename = os.path.join(yara_rules_dir, f"{name}.yar")
                        download_file(url, local_filename)
                        find_yara_matches(console,local_filename, file_path,name)
                else:
                    console.print("[bold red]\nTéléchargement des règles YARA ignoré. Exécution uniquement des règles locales.[/bold red]")
                    if not os.path.exists(yara_rules_dir):
                        os.makedirs(console,yara_rules_dir)
                    yara_files = [f for f in os.listdir(yara_rules_dir) if f.endswith(('.yar', '.rules', '.rule', '.yara'))]
                    if not yara_files:
                            console.print("[bold red]\nLe répertoire .yara_rules est vide. Aucune règle YARA locale à exécuter.[/bold red]")
                    else:
                            for local_rule in yara_files:
                                local_filename = os.path.join(yara_rules_dir, local_rule)
                                find_yara_matches(console,local_filename, file_path,local_rule)
        
        else:
                console.print("[bold red]Pas de connexion Internet détectée. Exécution uniquement des règles locales.[/bold red]")

    banner_text = Text("Affichage des strings identifiées par une réimplémentation de stringsifter (Merci Mandiant 💎)", justify="center", style="bold black on white")
    banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
    console.print(banner_panel,justify="center")
    console.print("\n[bold]💡Note: Vous pouvez également utiliser les commandes strings ou floss en association avec grep. 🔍\n [/bold]", justify="center")
    

    # Utiliser floss pour extraire les chaînes si le binaire est un exécutable Windows
    if proj.loader.main_object.os == 'windows':
        
        banner_text = Text("\nBinaire Windows 🪟 détecté. Utilisation de FLOSS de Mandiant pour extraire les chaînes de la stack.", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
        console.print(banner_panel,justify="center")
        try:
            with console.status("[bold bleue]Analyse en cours...[/bold bleue]", spinner="dots"):
                cfg = proj.analyses.CFGFast(resolve_indirect_jumps=False, force_complete_scan=False)
        except Exception as e:
            print(f"Erreur lors de la création du CFG: {e}")
            return
        floss_strings = extract_strings_with_floss(file_path)
        console.print(f"Extracted {len(floss_strings)} strings using FLOSS.")
        binary_strings.extend(floss_strings)


    display_strings_stringsifter(binary_strings, console)
    user_input = console.input("\n[bold]❓ Voulez-vous afficher toutes les chaînes du binaire (déconseillé car trop verbeux) ? (y/n):[/bold] ").strip().lower()
    if user_input == 'y' or user_input == '':
        console.print("\n")
        banner_text = Text("Affichage de toutes les strings du binaire", justify="center", style="bold black on white")
        banner_panel = Panel(banner_text, expand=False, border_style="bold yellow")
        console.print(banner_panel,justify="center")
        display_strings( binary_strings,console)
   

    check_aslr(console)
    html_content += console.export_html(inline_styles=True)
    save_to_html(html_content)


if __name__ == "__main__":
    main()