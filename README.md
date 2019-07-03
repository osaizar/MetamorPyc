# MetamorPyc
A simple and flexible metamorphic engine using radare2.

## Dependencies:
Pip install the requeriments:

```
$ pip3 install -r requeriments.txt
```

And install radare2's last version from it's [repository](https://github.com/radare/radare2).

## Running:
```
$ python3 metamorph.py -h
usage: MetamorPyc [-h] -i INPUT [-o OUTPUT] [-d]

A simple and flexible metamorphic engine using radare2.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to input executable/directory.
  -o OUTPUT, --output OUTPUT
                        Path to output executable/directory. Default:
                        meta.exe/meta for file/directory.
  -d, --debug           Enable debug messages during execution.
```

## Adding and editing architectures:
Base configuration files are provided in the [architectures](architectures/) folder. All the JSON fields are needed.

### Mutations
As shown in [x86_32.json](architectures/x86_32.json):
```
{"orig" : ["mov (e..), (e..)$"], "mutation" : [{"code" : "push {reg1}; pop {reg0}"}, {"code" : "push {reg1}; {nop}; pop {reg0}"}]}
```

Each mutation needs a "orig" tag with a instruction list in regex format and a list of posible mutations, the program will find instruction sets that coincide with all the regexes in "orig" and replace them with a random mutation in the "mutation" list.

Tags like {reg0}, {reg1}... can be used to use the variables from the regexes in the mutations. {nop} will add a random number of inocuous instructions.

---
Based on: [pymetangine](https://github.com/scmanjarrez/pymetangine)
