import random
import re
import json
import os
from itertools import combinations

ARCH_FOLDER = "architectures/"

class MetaEngine:


    def __init__(self, arch, bits):
        self.json = self.load_json(arch, bits)
        if self.json != None:
            try:
                self.bits = self.json["bits"]
                self.arch = self.json["arch"]
                self.mutable_ins = self.json["mutables"]
                self.regs = self.json["registers"]
                self.nops = self.json["nops"]
            except: # TODO: print Exception
                self.json = None


    def load_json(self, arch, bits):
        cfg = None

        for file in os.listdir(ARCH_FOLDER):
            if file.endswith(".json"):
                with open(os.path.join(ARCH_FOLDER, file), "r") as f:
                    cfg = json.load(f)

                if cfg["bits"] == bits and cfg["arch"] == arch: # TODO: add further checks
                    break
                else:
                    cfg = None

        return cfg


    def get_nop_instructions(self, size):
        if size == 0:
            return ""

        reg = random.choice(self.regs)
        combinate = random.randint(0,1)

        if self.nops["max"] < size or combinate == 1: # Combination of nops
            rnd = random.randint(1, min([self.nops["max"], size]))
            return self.get_nop_instructions(rnd) + self.get_nop_instructions(size - rnd)
        else:
            np = random.choice(self.nops[str(size)])
            return np.replace("{reg}", reg)+"; " # TODO: More than one register?


    def create_regexp(self):
        pass


    def generate_mutations(self, func, id):
        try:
            if func[id]["opcode"] == "mov eax, ebx":
                return False, 0
            elif "mov" in func[id]["opcode"]:
                # print ("{} ({:#x})".format(func[id]["opcode"], func[id]["offset"]))
                return "mov eax, ebx", 1 # DEBUG: Test that instruction mutation works.
            else:
                return False, 0
        except:
            print ("exception")
