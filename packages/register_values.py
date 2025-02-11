from rich.console import Console
from rich.table import Table
from rich.panel import Panel


def display_register_representation(console, arch_name):
    if arch_name in ["X86", "X86_64", "IA32", "IA64", "AMD64"]:
        display_x86_register_representation(console)
    elif arch_name in ["ARM", "ARM64", "AARCH64", "ARMv8", "ARMEL"]:
        display_arm_register_representation(console)
    elif arch_name in ["MIPS", "MIPS32", "MIPS64"]:
        display_mips_register_representation(console)
    elif arch_name in ["M68K", "MOTOROLA68K", "MOTOROLA68000"]:
        display_motorola_68000_register_representation(console)
    else:
        console.print(f"Unsupported architecture: {arch_name}")

def display_x86_register_representation(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Register", style="bold blue")
    table.add_column("Size", style="bold")
    table.add_column("Description", style="bold")

    table.add_row("[bold blue]RAX[/bold blue]", "64 bits", "Accumulator register")
    table.add_row("[bold blue]EAX[/bold blue]", "32 bits", "Lower 32 bits of RAX")
    table.add_row("[bold blue]AX[/bold blue]", "16 bits", "Lower 16 bits of EAX")
    table.add_row("[bold blue]AH[/bold blue]", "8 bits", "High 8 bits of AX")
    table.add_row("[bold blue]AL[/bold blue]", "8 bits", "Low 8 bits of AX")

    table.add_row("[bold blue]RBX[/bold blue]", "64 bits", "Base register")
    table.add_row("[bold blue]EBX[/bold blue]", "32 bits", "Lower 32 bits of RBX")
    table.add_row("[bold blue]BX[/bold blue]", "16 bits", "Lower 16 bits of EBX")
    table.add_row("[bold blue]BH[/bold blue]", "8 bits", "High 8 bits of BX")
    table.add_row("[bold blue]BL[/bold blue]", "8 bits", "Low 8 bits of BX")

    table.add_row("[bold blue]RCX[/bold blue]", "64 bits", "Counter register")
    table.add_row("[bold blue]ECX[/bold blue]", "32 bits", "Lower 32 bits of RCX")
    table.add_row("[bold blue]CX[/bold blue]", "16 bits", "Lower 16 bits of ECX")
    table.add_row("[bold blue]CH[/bold blue]", "8 bits", "High 8 bits of CX")
    table.add_row("[bold blue]CL[/bold blue]", "8 bits", "Low 8 bits of CX")

    table.add_row("[bold blue]RDX[/bold blue]", "64 bits", "Data register")
    table.add_row("[bold blue]EDX[/bold blue]", "32 bits", "Lower 32 bits of RDX")
    table.add_row("[bold blue]DX[/bold blue]", "16 bits", "Lower 16 bits of EDX")
    table.add_row("[bold blue]DH[/bold blue]", "8 bits", "High 8 bits of DX")
    table.add_row("[bold blue]DL[/bold blue]", "8 bits", "Low 8 bits of DX")

    register_panel = Panel(table, title="[bold blue]X86 Register Representation[/bold blue]", title_align="left", border_style="blue")
    console.print(register_panel)

def display_arm_register_representation(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Register", style="bold blue")
    table.add_column("Size", style="bold")
    table.add_column("Description", style="bold")

    for i in range(13):
        table.add_row(f"[bold blue]R{i}[/bold blue]", "32 bits", f"General purpose register {i}")
    table.add_row("[bold blue]SP[/bold blue]", "32 bits", "Stack pointer")
    table.add_row("[bold blue]LR[/bold blue]", "32 bits", "Link register")
    table.add_row("[bold blue]PC[/bold blue]", "32 bits", "Program counter")

    register_panel = Panel(table, title="[bold blue]ARM Register Representation[/bold blue]", title_align="left", border_style="blue")
    console.print(register_panel)

def display_mips_register_representation(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Register", style="bold blue")
    table.add_column("Size", style="bold")
    table.add_column("Description", style="bold")

    table.add_row("[bold blue]ZERO[/bold blue]", "32 bits", "Constant zero")
    table.add_row("[bold blue]AT[/bold blue]", "32 bits", "Assembler temporary")
    for i in range(2, 4):
        table.add_row(f"[bold blue]V{i-2}[/bold blue]", "32 bits", f"Function result {i-2}")
    for i in range(4, 8):
        table.add_row(f"[bold blue]A{i-4}[/bold blue]", "32 bits", f"Argument {i-4}")
    for i in range(8, 16):
        table.add_row(f"[bold blue]T{i-8}[/bold blue]", "32 bits", f"Temporary {i-8}")
    for i in range(16, 24):
        table.add_row(f"[bold blue]S{i-16}[/bold blue]", "32 bits", f"Saved {i-16}")
    for i in range(24, 26):
        table.add_row(f"[bold blue]T{i-16}[/bold blue]", "32 bits", f"Temporary {i-16}")
    table.add_row("[bold blue]K0[/bold blue]", "32 bits", "Reserved for OS kernel")
    table.add_row("[bold blue]K1[/bold blue]", "32 bits", "Reserved for OS kernel")
    table.add_row("[bold blue]GP[/bold blue]", "32 bits", "Global pointer")
    table.add_row("[bold blue]SP[/bold blue]", "32 bits", "Stack pointer")
    table.add_row("[bold blue]FP[/bold blue]", "32 bits", "Frame pointer")
    table.add_row("[bold blue]RA[/bold blue]", "32 bits", "Return address")

    register_panel = Panel(table, title="[bold blue]MIPS Register Representation[/bold blue]", title_align="left", border_style="blue")
    console.print(register_panel)

def display_motorola_68000_register_representation(console):
    table = Table(show_header=True, header_style="bold")
    table.add_column("Register", style="bold blue")
    table.add_column("Size", style="bold")
    table.add_column("Description", style="bold")

    for i in range(8):
        table.add_row(f"[bold blue]D{i}[/bold blue]", "32 bits", f"Data register {i}")
    for i in range(8):
        table.add_row(f"[bold blue]A{i}[/bold blue]", "32 bits", f"Address register {i}")
    table.add_row("[bold blue]PC[/bold blue]", "32 bits", "Program counter")
    table.add_row("[bold blue]SR[/bold blue]", "16 bits", "Status register")
    table.add_row("[bold blue]USP[/bold blue]", "32 bits", "User stack pointer")
    table.add_row("[bold blue]SSP[/bold blue]", "32 bits", "Supervisor stack pointer")

    register_panel = Panel(table, title="[bold blue]Motorola 68000 Register Representation[/bold blue]", title_align="left", border_style="blue")
    console.print(register_panel)

# Example usage
if __name__ == "__main__":
    console = Console()
    display_register_representation(console, "X86")
    display_register_representation(console, "ARM")
    display_register_representation(console, "MIPS")
    display_register_representation(console, "MOTOROLA68000")