#!/bin/sh

export DEBIAN_FRONTEND=noninteractive 
sudo apt update -y && sudo apt upgrade -y

sudo apt install -y \
    binutils curl file \
    gcc-mingw-w64 \
    python3 python3-pip \
    git

# setup nim
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

# install nimble packages
nimble install \
    winim