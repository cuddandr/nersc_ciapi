#!/bin/bash

#SBATCH -N 1
#SBATCH -C gpu
#SBATCH -G 1
#SBATCH -q shared
#SBATCH -J gh_runner
#SBATCH -A dune
#SBATCH -t 0:30:0
#SBATCH -n 1
#SBATCH -c 32

srun --cpu-bind=cores ./run.sh
