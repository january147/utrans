#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Wed Apr 22 16:08:14 2020
# Author: January

import os
import shutil
import platform

install_dir = "./utrans_installed"

pip_src = "https://pypi.tuna.tsinghua.edu.cn/simple"
try:
    import Crypto
    print("Crypto ok")
except:
    result = input("Crypto is not installted, should install it?(y or n)")
    if result.startswith("y"):
        os.system("pip3 install -i %s pycryptodome"%(pip_src))
    else:
        print("abort")
        exit(-1)

try:
    import progressbar
    print("progressbar ok")
except:
    result = input("progressbar is not installed, should install it?(y or n)")
    if result.startswith("y"):
        os.system("pip3 install -i %s progressbar"%(pip_src))
    else:
        print("abort")
        exit(-1)

try:
    import termcolor
    print("termcolor ok")
except:
    result = input("termcolor is not installted, should install it?(y or n)")
    if result.startswith("y"):
        os.system("pip3 install -i %s termcolor"%(pip_src))
    else:
        print("abort")
        exit(-1)

if platform.system() == "Windows":
    try:
        import colorama
        print("colorama ok")
    except:
        result = input("colorama is not installted, should install it?(y or n)")
        if result.startswith("y"):
            os.system("pip3 install -i %s colorama"%(pip_src))
        else:
            print("abort")
            exit(-1)


if not os.path.isdir(install_dir):
    os.mkdir(install_dir)

print("copy library")
shutil.copytree("./utrans", install_dir + "/utrans")
print("copy main program")
shutil.copyfile("./utrans_cmd.py", install_dir + "/utrans_cmd.py")
os.chmod(install_dir + "/utrans_cmd.py", 0o755)
print("install ok")

def main():
    pass
if __name__ == "__main__":
    main()
