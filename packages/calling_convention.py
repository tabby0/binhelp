from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def display_calling_convention(console, arch_name):
    if arch_name == "AMD64":
        display_system_v_amd64_calling_convention(console)
    elif arch_name == "X86":
        display_x86_global_calling_convention(console)
        console.print("\nVeuillez lire attentivement la section [bold blue]Detection Methods[/bold blue] et comparer en vue désassemblée ou en débugant.\n")
        display_detection_method(console)
        while True:
            
            console.print("Choisissez la convention d'appel :")
            console.print("[bold blue]0[/bold blue] - Passer")
            console.print("[bold blue]1[/bold blue] - cdecl")
            console.print("[bold blue]2[/bold blue] - stdcall")
            console.print("[bold blue]3[/bold blue] - fastcall")
            console.print("[bold blue]4[/bold blue] - thiscall")
            user_input = input("Entrez le numéro correspondant : ").strip()

            if user_input == '0':
                console.print("[bold yellow]Passage de la sélection de la convention d'appel.[/bold yellow]")
                break
            elif user_input == '1':
                display_cdecl_calling_convention(console)
                break
            elif user_input == '2':
                display_stdcall_calling_convention(console)
                break
            elif user_input == '3':
                display_fastcall_calling_convention(console)
                break
            elif user_input == '4':
                display_thiscall_calling_convention(console)
                break
            else:
                console.print("[bold red]Choix invalide. Veuillez réessayer.[/bold red]")
    elif arch_name == "ARMEL":
        display_arm_calling_convention(console)
    elif arch_name == "AARCH64":
        display_arm64_calling_convention(console)
    elif arch_name == "MIPS32":
        display_mips_calling_convention(console)
    elif arch_name == "MIPS64":
        display_mips64_calling_convention(console)
    elif arch_name == "X86_64":
        display_x64_windows_calling_convention(console)
    elif arch_name == "M68K" or arch_name == "M68K" or arch_name == "MOTOROLA68K" or arch_name == "MOTOROLA68000":
        display_motorola_68000_calling_convention(console)
    else:
        console.print(f"Unsupported architecture: {arch_name}")

def display_detection_method(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Convention", style="bold")
    table.add_column("Detection Method", style="bold")

    table.add_row("[bold blue]cdecl[/bold blue]", "Caller cleans the stack")
    table.add_row("[bold blue]stdcall[/bold blue]", "Callee cleans the stack")
    table.add_row("[bold blue]fastcall[/bold blue]", "First two arguments in ECX and EDX, rest on stack")
    table.add_row("[bold blue]thiscall[/bold blue]", "First argument (this pointer) in ECX, rest on stack")

    detection_panel = Panel(table, title="[bold blue]Detection Methods[/bold blue]", title_align="left", border_style="blue")
    console.print(detection_panel)

def display_x86_global_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]EIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]EAX[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][ESP][/bold red] → Return address (saved [bold red]EIP[/bold red]).\n"
                  "[bold red][ESP+4][/bold red] → Old [bold red]EBP[/bold red] (saved frame pointer).\n"
                  "[bold red][ESP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 4-byte aligned before the call.\n"
                  "Uses [bold red]ESP[/bold red] (stack pointer) and [bold red]EBP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][ESP][/bold red]", "Return Address ([bold red]EIP[/bold red])")
    stack_table.add_row("[bold red][ESP+4][/bold red]", "Old [bold red]EBP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][ESP+8][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]EAX[/bold red]", "1st argument")
    argument_table.add_row("[bold red]EDX[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]ECX[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)


def display_cdecl_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]EIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]EAX[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][ESP][/bold red] → Return address (saved [bold red]EIP[/bold red]).\n"
                  "[bold red][ESP+4][/bold red] → Old [bold red]EBP[/bold red] (saved frame pointer).\n"
                  "[bold red][ESP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 4-byte aligned before the call.\n"
                  "Uses [bold red]ESP[/bold red] (stack pointer) and [bold red]EBP[/bold red] (frame pointer if used).")

    detection_table = Table(show_header=False)
    detection_table.add_column("Convention", style="bold blue")
    detection_table.add_column("Detection Method", style="bold")
    detection_table.add_row("[bold red]cdecl[/bold red]", "Caller cleans the stack.")
    detection_table.add_row("[bold red]stdcall[/bold red]", "Callee cleans the stack.")
    detection_table.add_row("[bold red]fastcall[/bold red]", "First two arguments passed in [bold red]ECX[/bold red] and [bold red]EDX[/bold red].")
    detection_table.add_row("[bold red]thiscall[/bold red]", "First argument (this pointer) passed in [bold red]ECX[/bold red].")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    detection_panel = Panel(detection_table, title="[bold blue]Detection Methods[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(detection_panel)

def display_stdcall_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]EIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]EAX[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][ESP][/bold red] → Return address (saved [bold red]EIP[/bold red]).\n"
                  "[bold red][ESP+4][/bold red] → Old [bold red]EBP[/bold red] (saved frame pointer).\n"
                  "[bold red][ESP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 4-byte aligned before the call.\n"
                  "Uses [bold red]ESP[/bold red] (stack pointer) and [bold red]EBP[/bold red] (frame pointer if used).")

    detection_table = Table(show_header=False)
    detection_table.add_column("Convention", style="bold blue")
    detection_table.add_column("Detection Method", style="bold")
    detection_table.add_row("[bold red]cdecl[/bold red]", "Caller cleans the stack.")
    detection_table.add_row("[bold red]stdcall[/bold red]", "Callee cleans the stack.")
    detection_table.add_row("[bold red]fastcall[/bold red]", "First two arguments passed in [bold red]ECX[/bold red] and [bold red]EDX[/bold red].")
    detection_table.add_row("[bold red]thiscall[/bold red]", "First argument (this pointer) passed in [bold red]ECX[/bold red].")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    detection_panel = Panel(detection_table, title="[bold blue]Detection Methods[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(detection_panel)

def display_fastcall_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]EIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]EAX[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][ESP][/bold red] → Return address (saved [bold red]EIP[/bold red]).\n"
                  "[bold red][ESP+4][/bold red] → Old [bold red]EBP[/bold red] (saved frame pointer).\n"
                  "[bold red][ESP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 4-byte aligned before the call.\n"
                  "Uses [bold red]ESP[/bold red] (stack pointer) and [bold red]EBP[/bold red] (frame pointer if used).")

    detection_table = Table(show_header=False)
    detection_table.add_column("Convention", style="bold blue")
    detection_table.add_column("Detection Method", style="bold")
    detection_table.add_row("[bold red]cdecl[/bold red]", "Caller cleans the stack.")
    detection_table.add_row("[bold red]stdcall[/bold red]", "Callee cleans the stack.")
    detection_table.add_row("[bold red]fastcall[/bold red]", "First two arguments passed in [bold red]ECX[/bold red] and [bold red]EDX[/bold red].")
    detection_table.add_row("[bold red]thiscall[/bold red]", "First argument (this pointer) passed in [bold red]ECX[/bold red].")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    detection_panel = Panel(detection_table, title="[bold blue]Detection Methods[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(detection_panel)

def display_thiscall_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]EIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]EAX[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][ESP][/bold red] → Return address (saved [bold red]EIP[/bold red]).\n"
                  "[bold red][ESP+4][/bold red] → Old [bold red]EBP[/bold red] (saved frame pointer).\n"
                  "[bold red][ESP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 4-byte aligned before the call.\n"
                  "Uses [bold red]ESP[/bold red] (stack pointer) and [bold red]EBP[/bold red] (frame pointer if used).")

    detection_table = Table(show_header=False)
    detection_table.add_column("Convention", style="bold blue")
    detection_table.add_column("Detection Method", style="bold")
    detection_table.add_row("[bold red]cdecl[/bold red]", "Caller cleans the stack.")
    detection_table.add_row("[bold red]stdcall[/bold red]", "Callee cleans the stack.")
    detection_table.add_row("[bold red]fastcall[/bold red]", "First two arguments passed in [bold red]ECX[/bold red] and [bold red]EDX[/bold red].")
    detection_table.add_row("[bold red]thiscall[/bold red]", "First argument (this pointer) passed in [bold red]ECX[/bold red].")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    detection_panel = Panel(detection_table, title="[bold blue]Detection Methods[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(detection_panel)

def display_system_v_amd64_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]RIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]RAX[/bold red] (primary) and [bold red]RDX[/bold red] (secondary if needed).")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][RSP][/bold red] → Return address (saved [bold red]RIP[/bold red]).\n"
                  "[bold red][RSP+8][/bold red] → Old [bold red]RBP[/bold red] (saved frame pointer).\n"
                  "[bold red][RSP+16][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 16-byte aligned before the call.\n"
                  "Uses [bold red]RSP[/bold red] (stack pointer) and [bold red]RBP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][RSP][/bold red]", "Return Address ([bold red]RIP[/bold red])")
    stack_table.add_row("[bold red][RSP+8][/bold red]", "Old [bold red]RBP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][RSP+16][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]RDI[/bold red]", "1st argument")
    argument_table.add_row("[bold red]RSI[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]RDX[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]RCX[/bold red]", "4th argument")
    argument_table.add_row("[bold red]R8[/bold red]", "5th argument")
    argument_table.add_row("[bold red]R9[/bold red]", "6th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)

def display_arm64_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]PC[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]X0[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][SP][/bold red] → Return address (saved [bold red]PC[/bold red]).\n"
                  "[bold red][SP+8][/bold red] → Old [bold red]FP[/bold red] (saved frame pointer).\n"
                  "[bold red][SP+16][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 16-byte aligned before the call.\n"
                  "Uses [bold red]SP[/bold red] (stack pointer) and [bold red]FP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][SP][/bold red]", "Return Address ([bold red]PC[/bold red])")
    stack_table.add_row("[bold red][SP+8][/bold red]", "Old [bold red]FP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][SP+16][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]X0[/bold red]", "1st argument")
    argument_table.add_row("[bold red]X1[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]X2[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]X3[/bold red]", "4th argument")
    argument_table.add_row("[bold red]X4[/bold red]", "5th argument")
    argument_table.add_row("[bold red]X5[/bold red]", "6th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)

def display_arm_calling_convention(console):

    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]PC[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]R0[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][SP][/bold red] → Return address (saved [bold red]PC[/bold red]).\n"
                  "[bold red][SP+4][/bold red] → Old [bold red]FP[/bold red] (saved frame pointer).\n"
                  "[bold red][SP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 8-byte aligned before the call.\n"
                  "Uses [bold red]SP[/bold red] (stack pointer) and [bold red]FP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][SP][/bold red]", "Return Address ([bold red]PC[/bold red])")
    stack_table.add_row("[bold red][SP+4][/bold red]", "Old [bold red]FP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][SP+8][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]R0[/bold red]", "1st argument")
    argument_table.add_row("[bold red]R1[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]R2[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]R3[/bold red]", "4th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)

def display_mips_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]PC[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]V0[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                    "[bold red][SP][/bold red] → Return address (saved [bold red]PC[/bold red]).\n"
                    "[bold red][SP+4][/bold red] → Old [bold red]FP[/bold red] (saved frame pointer).\n"
                    "[bold red][SP+8][/bold red] → First spilled argument (if needed).\n"
                    "Stack must be 8-byte aligned before the call.\n"
                    "Uses [bold red]SP[/bold red] (stack pointer) and [bold red]FP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][SP][/bold red]", "Return Address ([bold red]PC[/bold red])")
    stack_table.add_row("[bold red][SP+4][/bold red]", "Old [bold red]FP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][SP+8][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]A0[/bold red]", "1st argument")
    argument_table.add_row("[bold red]A1[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]A2[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]A3[/bold red]", "4th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)

def display_mips64_calling_convention(console):

    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]PC[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]V0[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][SP][/bold red] → Return address (saved [bold red]PC[/bold red]).\n"
                  "[bold red][SP+8][/bold red] → Old [bold red]FP[/bold red] (saved frame pointer).\n"
                  "[bold red][SP+16][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 16-byte aligned before the call.\n"
                  "Uses [bold red]SP[/bold red] (stack pointer) and [bold red]FP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][SP][/bold red]", "Return Address ([bold red]PC[/bold red])")
    stack_table.add_row("[bold red][SP+8][/bold red]", "Old [bold red]FP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][SP+16][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]A0[/bold red]", "1st argument")
    argument_table.add_row("[bold red]A1[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]A2[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]A3[/bold red]", "4th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")    

def display_x64_windows_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]RIP[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]RAX[/bold red] (primary) and [bold red]RDX[/bold red] (secondary if needed).")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][RSP][/bold red] → Return address (saved [bold red]RIP[/bold red]).\n"
                  "[bold red][RSP+8][/bold red] → Old [bold red]RBP[/bold red] (saved frame pointer).\n"
                  "[bold red][RSP+16][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 16-byte aligned before the call.\n"
                  "Uses [bold red]RSP[/bold red] (stack pointer) and [bold red]RBP[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][RSP][/bold red]", "Return Address ([bold red]RIP[/bold red])")
    stack_table.add_row("[bold red][RSP+8][/bold red]", "Old [bold red]RBP[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][RSP+16][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]RCX[/bold red]", "1st argument")
    argument_table.add_row("[bold red]RDX[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]R8[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]R9[/bold red]", "4th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)

def display_motorola_68000_calling_convention(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Description", style="bold")
    table.add_column("Details", style="bold")

    table.add_row("[bold blue]Instruction Pointer[/bold blue]", "Stored in [bold red]PC[/bold red] before the call.")
    table.add_row("[bold blue]Return Value[/bold blue]", "Stored in [bold red]D0[/bold red].")
    table.add_row("[bold blue]Stack Frame Layout[/bold blue]", 
                  "[bold red][SP][/bold red] → Return address (saved [bold red]PC[/bold red]).\n"
                  "[bold red][SP+4][/bold red] → Old [bold red]A6[/bold red] (saved frame pointer).\n"
                  "[bold red][SP+8][/bold red] → First spilled argument (if needed).\n"
                  "Stack must be 4-byte aligned before the call.\n"
                  "Uses [bold red]SP[/bold red] (stack pointer) and [bold red]A6[/bold red] (frame pointer if used).")

    stack_table = Table(show_header=False)
    stack_table.add_column("Address", style="bold blue")
    stack_table.add_column("Description", style="bold")
    stack_table.add_row("[bold red][SP][/bold red]", "Return Address ([bold red]PC[/bold red])")
    stack_table.add_row("[bold red][SP+4][/bold red]", "Old [bold red]A6[/bold red] (frame ptr)")
    stack_table.add_row("[bold red][SP+8][/bold red]", "Argument 7+")

    argument_table = Table(show_header=False)
    argument_table.add_column("Register", style="bold blue")
    argument_table.add_column("Description", style="bold")
    argument_table.add_row("[bold red]D0[/bold red]", "1st argument")
    argument_table.add_row("[bold red]D1[/bold red]", "2nd argument")
    argument_table.add_row("[bold red]A0[/bold red]", "3rd argument")
    argument_table.add_row("[bold red]A1[/bold red]", "4th argument")
    argument_table.add_row("[bold red]Stack[/bold red]", "Additional arguments (right-to-left)")

    calling_convention_panel = Panel(table, title="[bold blue]Calling Convention[/bold blue]", title_align="left", border_style="blue")
    stack_layout_panel = Panel(stack_table, title="[bold blue]Stack Layout[/bold blue]", title_align="left", border_style="blue")
    argument_passing_panel = Panel(argument_table, title="[bold blue]Argument Passing[/bold blue]", title_align="left", border_style="blue")

    console.print(calling_convention_panel)
    console.print(argument_passing_panel)
    console.print(stack_layout_panel)