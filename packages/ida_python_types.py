from rich.console import Console
from rich.table import Table
from rich.panel import Panel

def display_data_type_equivalents(console: Console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Type C", style="bold blue")
    table.add_column("Taille (bits)", style="bold")
    table.add_column("Valeur Min", style="bold")
    table.add_column("Valeur Max", style="bold")
    table.add_column("Représentation", style="bold")

    data_types = [
        ("long long", 64, -(2**63), 2**63 - 1, "QWORD"),
        ("unsigned long long", 64, 0, 2**64 - 1, "QWORD"),
        ("double", 64, -(2**63), 2**63 - 1, "QWORD"),
        ("int", 32, -(2**31), 2**31 - 1, "DWORD"),
        ("unsigned int", 32, 0, 2**32 - 1, "DWORD"),
        ("long", 32, -(2**31), 2**31 - 1, "DWORD"),
        ("unsigned long", 32, 0, 2**32 - 1, "DWORD"),
        ("float", 32, -(2**31), 2**31 - 1, "DWORD"),
        ("short", 16, -(2**15), 2**15 - 1, "WORD"),
        ("unsigned short", 16, 0, 2**16 - 1, "WORD"),
        ("char", 8, -(2**7), 2**7 - 1, "BYTE"),
        ("unsigned char", 8, 0, 2**8 - 1, "BYTE"),
    ]

    for data_type in sorted(data_types, key=lambda x: x[1], reverse=True):
        table.add_row(f"[bold blue]{data_type[0]}[/bold blue]", str(data_type[1]), str(data_type[2]), str(data_type[3]), data_type[4])

    data_type_panel = Panel(table, title="[bold blue]Équivalents de Types de Données[/bold blue]", title_align="left", border_style="blue")
    console.print(data_type_panel)

    explanation = """
    [bold]Complément à Deux [/bold]

    Le complément à deux est la méthode la plus couramment utilisée pour représenter les nombres signés en binaire. Voici comment cela fonctionne :

    1. Représentation positive : Un nombre positif est représenté directement en binaire.
    2. Représentation négative :
       - On commence par la représentation binaire du nombre positif.
       - On inverse tous les bits (complément à un).
       - On ajoute 1 au résultat pour obtenir le complément à deux.

    Par exemple, sur 8 bits :
    - Le nombre 5 est représenté par 00000101.
    - Le nombre -5 est représenté par :
      - Complément à un de 00000101 : 11111010
      - Ajouter 1 : 11111011

    Ainsi, 11111011 est la représentation de -5 en complément à deux.

    Ainsi, selon que vous traitez une variable comme signée ou non signée, la même séquence de bits peut correspondre à deux valeurs différentes.

    [bold]Exemple :[/bold]
    - Motif binaire : 11111011
    - Signé : -5 (en complément à deux)
    - Non signé : 251
    """
    console.print(Panel(explanation, title="[bold blue]Explication[/bold blue]", border_style="blue"))

def display_ascii_explanation(console: Console):
    explanation = """
    [bold]Valeurs ASCII et Chaînes de Caractères en C[/bold]

    En C, les chaînes de caractères sont des tableaux de caractères terminés par un caractère nul (\\0). Voici quelques points importants à savoir :

    1. [bold]Valeurs ASCII[/bold] :
        - ASCII (American Standard Code for Information Interchange) est un code de caractères qui représente les lettres, chiffres et symboles.
        - Chaque caractère ASCII est représenté par un nombre entier compris entre 0 et 127.
        - Exemple : Le caractère 'A' a le code ASCII 65, et 'a' a le code ASCII 97.

    2. [bold]Chaînes de Caractères en C[/bold] :
        - Une chaîne de caractères est un tableau de caractères se terminant par un caractère nul (\\0).
        - Exemple : La chaîne "hello" est représentée en mémoire par les valeurs ASCII des caractères suivies d'un caractère nul : ['h', 'e', 'l', 'l', 'o', '\\0'].

    3. [bold]Représentation Hexadécimale des Chaînes[/bold] :
        - Les caractères peuvent être représentés par leurs codes ASCII en hexadécimal.
        - Exemple : La chaîne "hello" peut être représentée en hexadécimal comme \\x68\\x65\\x6c\\x6c\\x6f.

    4. [bold]Exemple de Chaîne en C[/bold] :
        - Chaîne : "hello"
        - Représentation en mémoire : ['h', 'e', 'l', 'l', 'o', '\\0']
        - Représentation hexadécimale : \\x68\\x65\\x6c\\x6c\\x6f\\x00

    [bold]Exemples :[/bold]
    - Caractère : 'h'
    - Valeur ASCII : 104
    - Valeur hexadécimale : 0x68
    """
    console.print(Panel(explanation, title="[bold blue]Valeurs ASCII et Chaînes de Caractères en C[/bold blue]", border_style="blue"))

   

def display_ascii_table(console: Console):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Caractère", style="bold cyan")
    table.add_column("Décimal", style="bold green")
    table.add_column("Hexadécimal", style="bold yellow")

    for i in range(32, 128):
        if i == 92:
            table.add_row(f"[bold cyan]\\[/bold cyan]", f"[bold green]92[/bold green]", f"[bold yellow]0x5c[/bold yellow]")
            continue
        char = chr(i)
        decimal = str(i)
        hexadecimal = hex(i)
        table.add_row(f"[bold cyan]{char}[/bold cyan]", f"[bold green]{decimal}[/bold green]", f"[bold yellow]{hexadecimal}[/bold yellow]")

    ascii_panel = Panel(table, title="[bold magenta]Table ASCII[/bold magenta]", title_align="left", border_style="magenta")
    console.print(ascii_panel)

def display_reverse_engineering_libraries(console: Console):
    table = Table(show_header=True, header_style="bold red")
    table.add_column("Library", style="bold cyan")
    table.add_column("Functionality", style="bold green")
    table.add_column("Example", style="bold")

    libraries = [
        ("binascii", "Convert between binary and ASCII (e.g., hexlify, unhexlify)",
         "import binascii\n"
         "# Convert binary data to hexadecimal representation\n"
         "hex_data = binascii.hexlify(b'hello')\n"
         "print(hex_data)  # b'68656c6c6f'\n"
         "# Convert hexadecimal representation back to binary data\n"
         "original_data = binascii.unhexlify(hex_data)\n"
         "print(original_data)  # b'hello'\n"
         "# Convert binary data to base64 representation\n"
         "base64_data = binascii.b2a_base64(b'hello')\n"
         "print(base64_data)  # b'aGVsbG8=\\n'\n"
         "# Convert base64 representation back to binary data\n"
         "original_data_base64 = binascii.a2b_base64(base64_data)\n"
         "print(original_data_base64)  # b'hello'"),
        
        ("struct", "Interpret bytes as packed binary data (e.g., pack, unpack)",
         "import struct\n"
         "# 1. Pack et unpack d'un entier (32 bits, little-endian)\n"
         "packed_data_1 = struct.pack('<I', 12345)  # '<I' : little-endian, unsigned int (4 octets)\n"
         "unpacked_data_1 = struct.unpack('<I', packed_data_1)\n"
         "print('1. Pack/Unpack entier (little-endian):', packed_data_1, unpacked_data_1)\n"
         "\n"
         "# 2. Pack et unpack d'un entier (32 bits, big-endian)\n"
         "packed_data_2 = struct.pack('>I', 12345)  # '>I' : big-endian, unsigned int (4 octets)\n"
         "unpacked_data_2 = struct.unpack('>I', packed_data_2)\n"
         "print('2. Pack/Unpack entier (big-endian):', packed_data_2, unpacked_data_2)\n"
         "\n"
         "# 3. Pack et unpack d'un flottant (32 bits, little-endian)\n"
         "packed_data_3 = struct.pack('<f', 3.14)  # '<f' : little-endian, float (4 octets)\n"
         "unpacked_data_3 = struct.unpack('<f', packed_data_3)\n"
         "print('3. Pack/Unpack flottant (little-endian):', packed_data_3, unpacked_data_3)\n"
         "\n"
         "# 4. Pack et unpack d'un double (64 bits, little-endian)\n"
         "packed_data_4 = struct.pack('<d', 3.14)  # '<d' : little-endian, double (8 octets)\n"
         "unpacked_data_4 = struct.unpack('<d', packed_data_4)\n"
         "print('4. Pack/Unpack double (little-endian):', packed_data_4, unpacked_data_4)\n"
         "\n"
         "# 5. Pack et unpack d'une chaîne de caractères\n"
         "packed_data_5 = struct.pack('10s', b'hello')  # '10s' : chaîne de 10 octets\n"
         "unpacked_data_5 = struct.unpack('10s', packed_data_5)\n"
         "print('5. Pack/Unpack chaîne de caractères:', packed_data_5, unpacked_data_5)\n"
         "\n"
         "# 6. Pack et unpack de plusieurs types de données\n"
         "packed_data_6 = struct.pack('<If10s', 42, 3.14, b'hello')  # '<If10s' : little-endian, int, float, chaîne de 10 octets\n"
         "unpacked_data_6 = struct.unpack('<If10s', packed_data_6)\n"
         "print('6. Pack/Unpack plusieurs types:', packed_data_6, unpacked_data_6)\n"
         "\n"
         "# 7. Pack et unpack avec un format personnalisé\n"
         "packed_data_7 = struct.pack('<hcl', 32767, b'A', 123456789)  # '<hcl' : little-endian, short, char, long\n"
         "unpacked_data_7 = struct.unpack('<hcl', packed_data_7)\n"
         "print('7. Pack/Unpack format personnalisé:', packed_data_7, unpacked_data_7)\n"
         "\n"
         "# 8. Pack et unpack avec répétition de données\n"
         "packed_data_8 = struct.pack('<3h', 1, 2, 3)  # '<3h' : little-endian, 3 shorts (16 bits)\n"
         "unpacked_data_8 = struct.unpack('<3h', packed_data_8)\n"
         "print('8. Pack/Unpack répétition de données:', packed_data_8, unpacked_data_8)\n"
         "\n"
         "# 9. Pack et unpack avec padding (remplissage)\n"
         "packed_data_9 = struct.pack('<xIx', 12345)  # '<xIx' : padding (1 octet), int (4 octets), padding (1 octet)\n"
         "unpacked_data_9 = struct.unpack('<xIx', packed_data_9)\n"
         "print('9. Pack/Unpack avec padding:', packed_data_9, unpacked_data_9)\n"
         "\n"
         "# 10. Pack et unpack avec des données hétérogènes\n"
         "packed_data_10 = struct.pack('<?hf', True, 32767, 3.14)  # '<?hf' : bool, short, float\n"
         "unpacked_data_10 = struct.unpack('<?hf', packed_data_10)\n"
         "print('10. Pack/Unpack données hétérogènes:', packed_data_10, unpacked_data_10)"),
        
        ("dis", "Disassemble Python bytecode into human-readable instructions",
         "import dis\n"
         "def example_function():\n"
         "    return 42\n"
         "dis.dis(example_function)"),
        
        ("ctypes", "Create and manipulate C data types in Python, call functions in DLLs/shared libraries",
         "import ctypes\n"
         "libc = ctypes.CDLL('libc.so.6')\n"
         "libc.printf(b'Hello, World!\\n')"),
    ]

    for library, functionality, example in libraries:
        table.add_row(f"[bold cyan]{library}[/bold cyan]", f"[bold green]{functionality}[/bold green]", f"[bold]{example}[/bold]\n")

    libraries_panel = Panel(table, title="[bold red]Reverse Engineering Libraries[/bold red]", title_align="left", border_style="red")
    console.print(libraries_panel)

def display_gef_commands(console: Console):
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Command", style="bold cyan")
    table.add_column("Description", style="bold green")
    table.add_column("Example", style="bold ")


    commands = [
        ("context", "Show registers, code, stack, and memory",
         "gef➤  context\n"
         " →   0x555555555145 main+4       mov    eax, 0x0\n"
         "     0x55555555514a main+9       call   0x555555555030 <gets@plt>\n"
         "     0x55555555514f main+14      mov    eax, 0x0\n"
         "──────────────────────────────────────────────\n"
         "$rax=0x1   $rbx=0x0   $rcx=0x7ffff7f9ba80   $rdx=0x0\n"
         "──────────────────────────────────────────────\n"
         "0x00007fffffffdf48│+0x00: 0x0000000000000001\n"
         "0x00007fffffffdf50│+0x08: 0x00007ffff7f9d700"),

        ("xinfo", "Show details of a memory address",
         "gef➤  xinfo $rsp\n"
         "Page: 0x7ffff7ff9000 → 0x7ffff7ffd000 (rw-)\n"
         "Path: [stack]\n"
         "Offset: 0x7fffffffdf48 - 0x7ffff7ff9000 = 0x6df48"),

        ("heap chunks", "Visualize the heap",
         "gef➤  heap chunks (or/and heap bins)\n"
         "[+] Heap chunks (inuse):\n"
         "    Chunk(addr=0x555555559010, size=0x250, flags=PREV_INUSE)\n"
         "    Chunk(addr=0x555555559260, size=0x230, flags=PREV_INUSE)"),

        ("grep", "Search for a pattern in memory",
         "gef➤  grep \"secret_key\"\n"
         "[+] Found 'secret_key' at 0x555555558040 → \"secret_key=abc123\""),

        ("checksec", "Check security features",
         "gef➤  checksec\n"
         "[+] checksec: NX enabled, Canary disabled, PIE disabled"),

        ("pattern create", "Create a pattern for buffer overflow",
         "gef➤  pattern create 50\n"
         "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaaka\n"
         "gef➤  pattern search $rsp\n"
         "[+] Found at offset 24"),

        ("dereference", "Dereference a memory address",
         "gef➤  dereference $rsp\n"
         "0x7fffffffdf48│+0x00: 0x00000001\n"
         "0x7fffffffdf50│+0x08: 0x00007ffff7f9d700"),

        ("ropgadget", "List ROP gadgets",
         "gef➤  ropgadget\n"
         "0x401016 ret\n"
         "0x40112c pop r12; pop r13; pop r14; pop r15; ret"),

        ("vmmap", "Show memory permissions",
         "gef➤  vmmap\n"
         "0x555555554000 0x555555555000 r-x /tmp/vuln\n"
         "0x7ffff7ff9000 0x7ffff7ffd000 r-- [vvar]"),

        ("catch syscall", "Set a breakpoint on a system call",
         "gef➤  catch syscall execve\n"
         "Catchpoint 1 (syscall 'execve' [59])"),

        ("heap-analysis-helper", "Analyze the heap",
         "gef➤  heap-analysis-helper\n"
         "[!] Double free detected at 0x555555559260"),

        ("capstone-disassemble", "Disassemble with color",
         "gef➤  capstone-disassemble $pc 3\n"
         "   0x401145 mov eax, 0x0\n"
         "   0x40114a call 0x401030\n"
         "   0x40114f mov eax, 0x0"),

        ("ptype", "Show complex types",
         "gef➤  ptype struct _IO_FILE\n"
         "struct _IO_FILE {\n"
         "    int _flags;\n"
         "    char *_IO_read_ptr;\n"
         "    [...]"),

        ("format-string-helper", "Exploit a format string vulnerability",
         "gef➤  format-string-helper\n"
         "[+] Possible format string vulnerability at 0x7fffffffdf48"),

        ("shellcode", "Generate shellcode",
         "gef➤  shellcode x86 execve\n"
         "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"),

        ("trace-run", "Trace execution",
         "gef➤  trace-run\n"
         "[0] 0x401145 mov eax, 0x0\n"
         "[1] 0x40114a call 0x401030"),

        ("xrefs", "Search for pointers",
         "gef➤  xrefs 0x401000\n"
         "[→] 0x401030: call 0x401000"),

        ("patch", "Write to memory",
         "gef➤  patch byte 0x401000 0x90  # Remplace par un NOP"),

        ("tui enable", "Enable TUI mode",
         "gef➤  tui enable  # Active l'interface\n"
         "gef➤  layout regs  # Affiche registres + code"),

        ("customize GEF", "Customize GEF",
         "echo \"source ~/.gdbinit-gef.py\" >> ~/.gdbinit\n"
         "echo \"set disassembly-flavor intel\" >> ~/.gdbinit"),
    ]

    for command, description, example in commands:
        table.add_row(f"[bold cyan]{command}[/bold cyan]\n", f"[bold green]{description}[/bold green]\n", f"[bold]{example}[/bold]\n")

    gdb_panel = Panel(table, title="[bold blue]GEF Commands[/bold blue]", title_align="left", border_style="blue")
    console.print(gdb_panel)

def display_pwn_commands(console: Console):
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Section", style="bold cyan")
    table.add_column("Description", style="bold green")
    table.add_column("Example", style="bold")

    commands = [
        ("Configuration de base", "Définit l'architecture et active les logs détaillés",
            "context(os='linux', arch='amd64')\n"
            "context.log_level = 'debug'"),

        ("Exploiter un binaire local", "Lance le binaire et envoie un payload",
            "p = process('./vuln')\n"
            "p.sendline(b'A' * 64)\n"
            "p.interactive()"),

        ("Exploiter une connexion réseau", "Connexion TCP et envoie de données",
            "r = remote('ctf.example.com', 1337)\n"
            "r.sendlineafter(b'> ', b'1')\n"
            "response = r.recvall()\n"
            "print(response.decode())"),

        ("Générer du shellcode", "Génère un shellcode execve('/bin/sh')",
            "shellcode = asm(shellcraft.sh())\n"
            "print(hexdump(shellcode))"),

        ("Créer des patterns pour buffer overflow", "Génère un motif cyclique et trouve l'offset",
            "pattern = cyclic(100)\n"
            "offset = cyclic_find(0x61616164)\n"
            "print(f'Offset: {offset}')"),

        ("Lire/Écrire avec les registres", "Charge le binaire et initialise ROP",
            "elf = ELF('./vuln')\n"
            "rop = ROP(elf)\n"
            "rop.call('puts', [elf.got['puts']])\n"
            "print(rop.dump())"),

        ("Pack/Unpack des valeurs", "Pack et unpack de valeurs 64 bits",
            "packed = p64(0xdeadbeef)\n"
            "unpacked = u64(b'\\xef\\xbe\\xad\\xde\\x00\\x00\\x00\\x00')\n"
            "print(f'Unpacked: {hex(unpacked)}')"),

        ("Interagir avec GDB", "Attache GDB avec des commandes",
            "gdb.attach(p, '''\n"
            "break *main+10\n"
            "continue\n"
            "''')"),

        ("Exploit template (buffer overflow)", "Payload avec ROP chain et shellcode",
            "payload = flat({\n"
            "    32: rop.chain(),\n"
            "    64: shellcode\n"
            "})\n"
            "p.sendline(payload)"),

        ("Trouver des gadgets", "Recherche d'adresses et de strings",
            "elf = ELF('./vuln')\n"
            "print(hex(elf.address))\n"
            "print(hex(elf.sym['main']))\n"
            "print(hex(next(elf.search(b'/bin/sh'))))"),

        ("Bruteforce/Fuzzing", "Essai de payloads multiples",
            "for i in range(100):\n"
            "    try:\n"
            "        p = process('./vuln')\n"
            "        p.sendline(fmtstr_payload(i, {0x404000: 0xdeadbeef}))\n"
            "        p.recvall()\n"
            "    except EOFError:\n"
            "        pass"),

        ("Format String Exploit", "Payload pour exploiter une vulnérabilité de format string",
            "payload = fmtstr_payload(6, {elf.got['puts']: elf.sym['win']})\n"
            "p.sendline(payload)"),

        ("Travailler avec les fichiers ELF", "Manipulation des fichiers ELF et libc",
            "libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')\n"
            "libc.address = 0x7ffff7dc2000\n"
            "system = libc.sym['system']"),

        ("Utilitaires", "Fonctions utilitaires pour le debugging",
            "print(enhex(b'AAAA'))\n"
            "print(unhex('41414141'))\n"
            "pause()"),
    ]

    for section, description, example in commands:
        table.add_row(f"[bold cyan]{section}[/bold cyan]", f"[bold green]{description}[/bold green]", f"[bold]{example}[/bold]\n")

    pwn_panel = Panel(table, title="[bold blue]Pwntools Commands[/bold blue]", title_align="left", border_style="blue")
    console.print(pwn_panel)


