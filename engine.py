import random
import re
from itertools import combinations

class MetaEngine:
    def __init__(self, bits):
        self.bits = bits
        self.create_regexp()

    def get_nop_instructions(self, size):
        pass

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
