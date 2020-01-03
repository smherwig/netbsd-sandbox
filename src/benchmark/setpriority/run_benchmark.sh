#!/bin/sh

num=10000000

printf "normal\n"
time ./normal $num
printf "\n"

printf "boolean\n"
time ./boolean_rule $num
printf "\n"

printf "func\n"
time ./func_rule $num

