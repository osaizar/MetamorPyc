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
                self.mutations = self.json["mutations"]
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
        combinate = random.randint(0,1) # TODO: Adjust probability

        if self.nops["max"] < size or combinate == 1: # Combination of nops
            rnd = random.randint(1, min([self.nops["max"], size]))
            return self.get_nop_instructions(rnd) + self.get_nop_instructions(size - rnd)
        else:
            np = random.choice(self.nops[str(size)])
            return np.replace("{reg}", reg)+"; " # TODO: More than one register?


    def generate_mutations(self, func, id):
        mutations = []
        for mut in self.mutations:
            valid = True
            regs = []

            for i, m in enumerate(mut["orig"]):
                match = re.match(m, func[id+i]["opcode"])
                if match is not None:
                    regs += list(match.groups())
                else:
                    valid = False
                    break

            if valid:
                mutation = random.choice(mut["mutation"])
                mutcode = mutation["code"]

                for i, r in enumerate(regs):
                    mutcode = mutcode.replace("{reg"+str(i)+"}", r)

                rnd = random.randint(1,4) # TODO: How many nops?
                mutcode = mutcode.replace("{nop}", self.get_nop_instructions(rnd))

                mutations.append((mutcode, len(mut["orig"])))

        if len(mutations) != 0:
            return random.choice(mutations) # Return (mutation, jump) touple
        else:
            return "", 0
