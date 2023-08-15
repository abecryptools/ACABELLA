#!/bin/sh

eval `opam config env`
make
export GGM_PATH=/root/ggm-symbolic-solver/
cd web && make

