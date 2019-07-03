import sys
import r2pipe
import argparse
import engine as me
import keystone as ks
from termcolor import colored
from os import listdir, mkdir
from os.path import isfile, isdir, join, exists
import shutil
import traceback

DEBUG = False
KS = None
META = None
total_ins = 0 # TODO: global?

total_length = 0

def print_debug(str, color):
    if DEBUG:
        print(colored(str, color))


def get_ks(arch, arch_bits): # TODO: What architectures are supported by KS?
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

    print(colored("[INFO] Total number of mutations: {}/{} total length {}"
          .format(len(mutations), total_ins, total_length), "cyan"))


def configure_environment(args):
    global KS, META, total_ins
    shutil.copyfile(args.input, args.output)

    print(colored("[INFO] Opening {} in radare2.".format(args.input), "cyan"))
    r2 = r2pipe.open(args.output, ["-w", "-2"]) # -w write and -2 shut up stderr

    print_debug("[DEBUG] Analyzing architecture of the executable.", "green")
    exe_info = r2.cmdj('ij')

    if "bin" not in exe_info:
        print(colored("[ERROR] File format not supported.", "red"))
        return None

    arch_bits = exe_info['bin']['bits']
    arch = exe_info['bin']['arch']
    print(colored("[INFO] Detected {} {} bits architecture.".format(arch, arch_bits), "cyan"))

    KS = get_ks(arch, arch_bits)
    META = me.MetaEngine(arch, arch_bits)

    if META.json == None:
        print(colored("[ERROR] Couldn't load a config file for {} {} architecture.".format(exe_info['bin']['arch'], exe_info['bin']['bits']), "red"))
        return None

    print(colored("[INFO] Loaded '{}' config file".format(META.json["name"]), "cyan"))

    print(colored("[INFO] Analyzing executable code.", "cyan"))
    r2.cmd('aaa')

    return r2


def mutate_function(args, func):
    global total_ins
    global total_length
    mutations = []
    n_ins = len(func["ops"])
    total_length += n_ins

    jump = 0
    for i, ins in enumerate(func["ops"]):
        if jump > 0:
            jump -= 1
            continue

        if "type" not in ins or ins["type"] not in META.mutable_ins:
            continue

        meta = META.generate_mutations(func["ops"], i)
        mutation, jump = meta
        if mutation:
            bytes = generate_bytes(mutation)
            mutations.append({"offset": ins["offset"], "bytes": bytes})
            print_debug("[DEBUG] Mutating instruction ({:#x}): {:20s} -->    {:30s}"
                  .format(ins["offset"], ins["opcode"],
                          mutation if mutation else ins["opcode"]), "green" if mutation else "magenta")
        else:
            pass

        total_ins += 1


    return mutations


def get_mutations(functions):
    mutations = []
    for func in functions:
        if func["type"] == "fcn" and "name" in func:
            try:
                func_code = r2.cmdj("pdfj @{}".format(func["name"]))

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
                if DEBUG:
                    print(colored("[ERROR] Exception {}".format(traceback.format_exc()), "red"))

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

    argparser = argparse.ArgumentParser(prog="MetamorPhyc",
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
