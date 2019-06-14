import sys
import r2pipe
import argparse
import engine as me
from termcolor import colored
from os import listdir, mkdir
from os.path import isfile, isdir, join, exists

SUP_ARCH = ["x86"] # Supported architectures

DEBUG = False
KS = None
META = None
total_ins = 0

def print_debug(str, color):
    if DEBUG:
        print(colored(str, color))


def get_ks(arch, arch_bits):
    if arch == "x86":
        ks_arch = ks.KS_ARCH_X86
        if arch_bits == 32:
            ks_mode = ks.KS_MODE_32
        else:
            ks_mode = ks.KS_MODE_64
    else:
        return None

    return ks.Ks(ks_arch, ks_mode)


def generate_bytes(code):
    asm, _ = KS.asm(code)
    return "".join(["{:02x}".format(ins) for ins in asm])


def patch_executable(args, r2, mutations):
    print(colored("[INFO] Writing mutations to {}".format(args.output), "cyan"))
    for idx, mutation in enumerate(mutations):
        r2.cmd("wx {} @{}".format(mutation["bytes"], mutation["offset"]))

    print(colored("[INFO] Total number of mutations: {}/{}"
          .format(len(list_mutations), total_ins), "cyan"))


def configure_environment(args):
    global KS, META, total_ins
    shutil.copyfile(args.input, args.output)

    print(colored("[INFO] Opening {} in radare2.".format(args.input), "cyan"))
    r2 = r2pipe.open(args.output, ["-w", "-2"]) # -w write and -2 shut up stderr

    print_debug(colored("[DEBUG] Analyzing architecture of the executable.", "green"))
    exe_info = r2.cmdj('ij')

    if "bin" not in exe_info:
        print(colored("[ERROR] File format not supported.", "red"))
        return None

    if exe_info['bin']['arch'] not in SUP_ARCH:
        print(colored("[ERROR] Architecture {} not supported.".format(exe_info['bin']['arch']), "red"))
        return None

    arch_bits = exe_info['bin']['bits']
    arch = exe_info['bin']['arch'
    print(colored("[INFO] Detected {} {} bits architecture.".format(arch, arch_bits), "cyan")

    print(colored("[INFO] Analyzing executable code.", "cyan"))
    r2.cmd('aaa')

    KS = get_ks(arch, arch_bits)
    META = me.MetaEngine(arch_bits)

    return r2


def get_mutations(functions):
    mutations = []
    for func in functions:
        if func["type"] == "fcn":
            try:
                func_code = r2.cmdj("pdfj @{}".format(fun["name"]))

                if func_code is None:
                    print(colored("[INFO] Function {} has no code".format(func["name"]), "cyan"))
                elif "ops" not in func_code:
                    print(colored("[INFO] Function {} has no ops".format(func["name"]), "cyan"))
                else:
                    mutation = mutate_function(args, func_code)
                    if mutation is not None and mutation: # TODO: True or False or None
                        mutations.append(mutation)
            except Exception as error:
                print(colored("[ERROR] Function {} could not be disassembled".format(func["name"]), "red"))
                print(colored("[ERROR] Exception {}".format(error), "red"))

    mutations = [dict for sub_list in mutations for dict in sub_list]

    return mutations


def main(args, r2):
    print(colored("[INFO] Loading functions information.", "cyan"))
    functions = r2.cmdj("aflj")

    if functions is None:
        print(colored("[ERROR] Could not load any function.", "red"))
        return False

    print(colored("[INFO] Loading mutations.", "cyan"))
    mutations = get_mutations(functions)

    print(colored("[INFO] Starting patching routine.", "cyan"))
    patch_executable(args, r2, mutations)


def parse_arguments():
    global DEBUG

    argparser = argparse.ArgumentParser(prog="pymetangine",
                                        description='A python metamorphic engine for PE/PE+ using radare2.')
    argparser.add_argument('-i', '--input', required=True,
                           help='Path to input executable/directory.')
    argparser.add_argument('-o', '--output', default=['meta.exe', 'meta'],
                           help='Path to output executable/directory. Default: meta.exe/meta for file/directory.')
    argparser.add_argument('-d', '--debug', action='store_true',
                           help='Enable debug messages during execution.')
    argparser.add_argument('-r', '--random', choices=['y', 'n'], default='y',
                           help='Change mode of replacements, random/all substitutions.')

    args = argparser.parse_args()

    DEBUG = args.debug

    print_debug("[DEBUG] Parsing arguments.", "green")

    return args


if __name__ == "__main__":
    args = parse_arguments()
    r2 = configure_environment(args)
    if r2 is not None:
        main(args, r2)
        r2.quit()

    print(colored("[INFO] Exiting...\n", "cyan"))