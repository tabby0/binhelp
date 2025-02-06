def extract_strings(proj):
    import re
    glibc_patterns = [
        b'GNU C Library', b'glibc', b'GNU', b'Free Software Foundation',
        b'__libc_start_main', b'__GI_', b'__libc_', b'__libc_init', b'__libc_csu'
    ]
    binary_strings = []
    for sec in proj.loader.main_object.sections:
        if sec.is_readable :
            try:
                data = proj.loader.memory.load(sec.vaddr, sec.memsize)
                strings = re.findall(rb'[\x21-\x7E]{10,}', data)
                for s in strings:
                    if not any(pattern in s for pattern in glibc_patterns):
                        binary_strings.extend([s])
            except KeyError:
                print(f"Erreur: Impossible de charger les données à l'adresse {sec.vaddr:#x}")
    return binary_strings


def analyze_functions(cfg,console, functions_dict):
    from rich.table import Table
    import yara
    function_name = functions_dict['nom_du_dictionnaire']
    table = Table(title=f"Fonctions trouvées : {function_name}", show_header=True, header_style="bold yellow") 
    table.add_column("Nom de la fonction", style="cyan")
    table.add_column("Description", style="bold yellow")
    table.add_column("Adresse", style="green")

    for func_addr, func in cfg.functions.items():
        if func.name in functions_dict:
            description = functions_dict[func.name]
            table.add_row(func.name, description, f"{func_addr:#x}")
            table.add_row("", "", "") 

    if table.row_count > 0:
        console.print(table)
        console.print('\n')