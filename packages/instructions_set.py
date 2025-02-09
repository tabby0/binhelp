from rich.console import Console
from rich.table import Table
from rich.panel import Panel

def print_instruction_set(console: Console, arch_name: str):
    if arch_name == "X86" or arch_name == "X86_64" or arch_name == "IA32" or arch_name == "IA64" or arch_name == "AMD64":
        print_x86_instruction_set(console)
    elif arch_name == "ARM" or arch_name == "ARM64" or arch_name == "AARCH64" or arch_name == "ARMv8" or arch_name == "ARMEL":
        print_arm_instruction_set(console)
    elif arch_name == "MIPS" or arch_name == "MIPS32" or arch_name == "MIPS64":
        print_mips_instruction_set(console)
    elif arch_name == "M68K" or arch_name == "MOTOROLA68K" or arch_name == "MOTOROLA68000":
        print_motorolla68k_instruction_set(console)
    else:
        console.print(f"Unsupported architecture: {arch_name}")

def print_x86_instruction_set(console: Console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Instruction", style="bold blue")
    table.add_column("Description", style="bold")

    table.add_row("[bold blue]MOV[/bold blue]", "MOV AX, BX  ; Déplace la valeur de BX dans AX\n")
    table.add_row("[bold blue]ADD[/bold blue]", "ADD AX, BX  ; Ajoute la valeur de BX à AX\n")
    table.add_row("[bold blue]SUB[/bold blue]", "SUB AX, BX  ; Soustrait la valeur de BX de AX\n")
    table.add_row("[bold blue]MUL[/bold blue]", "MUL BX  ; Multiplie AX par BX\n")
    table.add_row("[bold blue]DIV[/bold blue]", "DIV BX  ; Divise AX par BX\n")
    table.add_row("[bold blue]PUSH[/bold blue]", "PUSH AX  ; Empile la valeur de AX sur la pile\n")
    table.add_row("[bold blue]POP[/bold blue]", "POP AX  ; Dépile la valeur du sommet de la pile dans AX\n")
    table.add_row("[bold blue]CMP[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\n")
    table.add_row("[bold blue]JMP[/bold blue]", "JMP 0x0040  ; Saute à l'adresse 0x0040\n")
    table.add_row("[bold blue]CALL[/bold blue]", "CALL 0x0040  ; Appelle la procédure à l'adresse 0x0040\n")
    table.add_row("[bold blue]RET[/bold blue]", "RET  ; Retourne à l'appelant\n")
    table.add_row("[bold blue]JE[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\nJE 0x0040  ; Saute à l'adresse 0x0040 si AX == BX\n")
    table.add_row("[bold blue]JNE[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\nJNE 0x0040  ; Saute à l'adresse 0x0040 si AX != BX\n")
    table.add_row("[bold blue]JG[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\nJG 0x0040  ; Saute à l'adresse 0x0040 si AX > BX\n")
    table.add_row("[bold blue]JL[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\nJL 0x0040  ; Saute à l'adresse 0x0040 si AX < BX\n")
    table.add_row("[bold blue]JGE[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\nJGE 0x0040  ; Saute à l'adresse 0x0040 si AX >= BX\n")
    table.add_row("[bold blue]JLE[/bold blue]", "CMP AX, BX  ; Compare AX avec BX\nJLE 0x0040  ; Saute à l'adresse 0x0040 si AX <= BX\n")

    instruction_panel = Panel(table, title="[bold blue]Instructions X86[/bold blue]", title_align="left", border_style="blue")
    console.print(instruction_panel)

def print_arm_instruction_set(console: Console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Instruction", style="bold blue")
    table.add_column("Description", style="bold")

    table.add_row("[bold blue]MOV[/bold blue]", "MOV R0, R1  ; Déplace la valeur de R1 dans R0\n")
    table.add_row("[bold blue]ADD[/bold blue]", "ADD R0, R1, R2  ; Ajoute la valeur de R1 et R2, résultat dans R0\n")
    table.add_row("[bold blue]SUB[/bold blue]", "SUB R0, R1, R2  ; Soustrait la valeur de R2 de R1, résultat dans R0\n")
    table.add_row("[bold blue]MUL[/bold blue]", "MUL R0, R1, R2  ; Multiplie R1 par R2, résultat dans R0\n")
    table.add_row("[bold blue]DIV[/bold blue]", "DIV R0, R1, R2  ; Divise R1 par R2, résultat dans R0\n")
    table.add_row("[bold blue]PUSH[/bold blue]", "PUSH {R0}  ; Empile la valeur de R0 sur la pile\n")
    table.add_row("[bold blue]POP[/bold blue]", "POP {R0}  ; Dépile la valeur du sommet de la pile dans R0\n")
    table.add_row("[bold blue]B[/bold blue]", "B 0x0040  ; Branche à l'adresse 0x0040\n")
    table.add_row("[bold blue]BL[/bold blue]", "BL 0x0040  ; Branche avec lien à l'adresse 0x0040\n")
    table.add_row("[bold blue]BX[/bold blue]", "BX R0  ; Branche à l'adresse dans R0\n")
    table.add_row("[bold blue]BEQ[/bold blue]", "CMP R0, R1  ; Compare R0 avec R1\nBEQ 0x0040  ; Branche à l'adresse 0x0040 si R0 == R1\n")
    table.add_row("[bold blue]BNE[/bold blue]", "CMP R0, R1  ; Compare R0 avec R1\nBNE 0x0040  ; Branche à l'adresse 0x0040 si R0 != R1\n")
    table.add_row("[bold blue]BGT[/bold blue]", "CMP R0, R1  ; Compare R0 avec R1\nBGT 0x0040  ; Branche à l'adresse 0x0040 si R0 > R1\n")
    table.add_row("[bold blue]BLT[/bold blue]", "CMP R0, R1  ; Compare R0 avec R1\nBLT 0x0040  ; Branche à l'adresse 0x0040 si R0 < R1\n")
    table.add_row("[bold blue]BGE[/bold blue]", "CMP R0, R1  ; Compare R0 avec R1\nBGE 0x0040  ; Branche à l'adresse 0x0040 si R0 >= R1\n")
    table.add_row("[bold blue]BLE[/bold blue]", "CMP R0, R1  ; Compare R0 avec R1\nBLE 0x0040  ; Branche à l'adresse 0x0040 si R0 <= R1\n")

    instruction_panel = Panel(table, title="[bold blue]Instructions ARM[/bold blue]", title_align="left", border_style="blue")
    console.print(instruction_panel)

def print_mips_instruction_set(console: Console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Instruction", style="bold blue")
    table.add_column("Description", style="bold")

    table.add_row("[bold blue]ADD[/bold blue]", "ADD $t0, $t1, $t2  ; Ajoute la valeur de $t1 et $t2, résultat dans $t0\n")
    table.add_row("[bold blue]SUB[/bold blue]", "SUB $t0, $t1, $t2  ; Soustrait la valeur de $t2 de $t1, résultat dans $t0\n")
    table.add_row("[bold blue]MUL[/bold blue]", "MUL $t0, $t1, $t2  ; Multiplie $t1 par $t2, résultat dans $t0\n")
    table.add_row("[bold blue]DIV[/bold blue]", "DIV $t0, $t1, $t2  ; Divise $t1 par $t2, résultat dans $t0\n")
    table.add_row("[bold blue]LW[/bold blue]", "LW $t0, 0($t1)  ; Charge un mot depuis l'adresse $t1 dans $t0\n")
    table.add_row("[bold blue]SW[/bold blue]", "SW $t0, 0($t1)  ; Stocke un mot de $t0 à l'adresse $t1\n")
    table.add_row("[bold blue]BEQ[/bold blue]", "BEQ $t0, $t1, 0x0040  ; Branche à l'adresse 0x0040 si $t0 == $t1\n")
    table.add_row("[bold blue]BNE[/bold blue]", "BNE $t0, $t1, 0x0040  ; Branche à l'adresse 0x0040 si $t0 != $t1\n")
    table.add_row("[bold blue]J[/bold blue]", "J 0x0040  ; Saute à l'adresse 0x0040\n")
    table.add_row("[bold blue]JAL[/bold blue]", "JAL 0x0040  ; Saute et lie à l'adresse 0x0040\n")
    table.add_row("[bold blue]JR[/bold blue]", "JR $t0  ; Saute à l'adresse dans $t0\n")
    table.add_row("[bold blue]JALR[/bold blue]", "JALR $t0  ; Saute et lie à l'adresse dans $t0\n")
    table.add_row("[bold blue]BGTZ[/bold blue]", "BGTZ $t0, 0x0040  ; Branche à l'adresse 0x0040 si $t0 > 0\n")
    table.add_row("[bold blue]BLTZ[/bold blue]", "BLTZ $t0, 0x0040  ; Branche à l'adresse 0x0040 si $t0 < 0\n")
    table.add_row("[bold blue]BGEZ[/bold blue]", "BGEZ $t0, 0x0040  ; Branche à l'adresse 0x0040 si $t0 >= 0\n")
    table.add_row("[bold blue]BLEZ[/bold blue]", "BLEZ $t0, 0x0040  ; Branche à l'adresse 0x0040 si $t0 <= 0\n")

    instruction_panel = Panel(table, title="[bold blue]Instructions MIPS[/bold blue]", title_align="left", border_style="blue")
    console.print(instruction_panel)

def print_motorolla68k_instruction_set(console: Console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Instruction", style="bold blue")
    table.add_column("Description", style="bold")

    table.add_row("[bold blue]MOVE[/bold blue]", "MOVE D0, D1  ; Déplace la valeur de D1 dans D0\n")
    table.add_row("[bold blue]ADD[/bold blue]", "ADD D0, D1  ; Ajoute la valeur de D1 à D0\n")
    table.add_row("[bold blue]SUB[/bold blue]", "SUB D0, D1  ; Soustrait la valeur de D1 de D0\n")
    table.add_row("[bold blue]MULS[/bold blue]", "MULS D1, D0  ; Multiplie D0 par D1 (signé)\n")
    table.add_row("[bold blue]DIVS[/bold blue]", "DIVS D1, D0  ; Divise D0 par D1 (signé)\n")
    table.add_row("[bold blue]MOVEA[/bold blue]", "MOVEA A0, A1  ; Déplace l'adresse de A1 dans A0\n")
    table.add_row("[bold blue]MOVEQ[/bold blue]", "MOVEQ #10, D0  ; Déplace la valeur immédiate 10 dans D0\n")
    table.add_row("[bold blue]BRA[/bold blue]", "BRA 0x0040  ; Branche à l'adresse 0x0040\n")
    table.add_row("[bold blue]BSR[/bold blue]", "BSR 0x0040  ; Branche à l'adresse 0x0040 et sauvegarde le retour\n")
    table.add_row("[bold blue]BEQ[/bold blue]", "CMP D0, D1  ; Compare D0 avec D1\nBEQ 0x0040  ; Branche à l'adresse 0x0040 si D0 == D1\n")
    table.add_row("[bold blue]BNE[/bold blue]", "CMP D0, D1  ; Compare D0 avec D1\nBNE 0x0040  ; Branche à l'adresse 0x0040 si D0 != D1\n")
    table.add_row("[bold blue]BGT[/bold blue]", "CMP D0, D1  ; Compare D0 avec D1\nBGT 0x0040  ; Branche à l'adresse 0x0040 si D0 > D1\n")
    table.add_row("[bold blue]BLT[/bold blue]", "CMP D0, D1  ; Compare D0 avec D1\nBLT 0x0040  ; Branche à l'adresse 0x0040 si D0 < D1\n")
    table.add_row("[bold blue]BGE[/bold blue]", "CMP D0, D1  ; Compare D0 avec D1\nBGE 0x0040  ; Branche à l'adresse 0x0040 si D0 >= D1\n")
    table.add_row("[bold blue]BLE[/bold blue]", "CMP D0, D1  ; Compare D0 avec D1\nBLE 0x0040  ; Branche à l'adresse 0x0040 si D0 <= D1\n")
    table.add_row("[bold blue]JMP[/bold blue]", "JMP 0x0040  ; Saute à l'adresse 0x0040\n")
    table.add_row("[bold blue]JSR[/bold blue]", "JSR 0x0040  ; Saute à l'adresse 0x0040 et sauvegarde le retour\n")
    table.add_row("[bold blue]RTS[/bold blue]", "RTS  ; Retourne de la sous-routine\n")

    instruction_panel = Panel(table, title="[bold blue]Instructions Motorola 68000[/bold blue]", title_align="left", border_style="blue")
    console.print(instruction_panel)