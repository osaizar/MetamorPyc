#!/usr/bin/python3
import os

os.system("rm  ~/Makina\ Birtualak/konpartitua/samples/*")

files = os.listdir('samples')

for f in files:
    if "_out" not in f:
        os.system("python3 metamorph.py -d -i samples/{} -o samples/{}_out && cp samples/{}_out ~/Makina\ Birtualak/konpartitua/samples/{}".format(f,f,f,f))

os.system("rm samples/*_out")
