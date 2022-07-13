#!bin/bash
# Test system call for different passwords

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to test system call for different passwords!${normal}\n"

rm -rf test08_input, test08_output
touch test08_input
touch test08_output

./xhw1 -p "aditikandoi" -e test08_input test08_output > test08_arg1
./xhw1 -p "assignment" -d test08_output test08_input > test08_arg2

echo "Testing: PROVIDING DIFFERENT PASSWORDS"

if grep -q "syscall returned -1 (errno=13)" test08_arg2;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi

rm -rf test08_password test08_input test08_output test08_arg2 test08_arg1

echo -e "--------------------------------------------------------------\n"

rm -rf test08_input, test08_output, test08_temp
touch test08_input 
touch test08_temp
touch test08_output

./xhw1 -p "aditikandoi" -e test08_input test08_temp > test08_arg1
./xhw1 -p "aditikandoi" -d test08_temp test08_output > test08_arg2

echo "Testing: PROVIDING SAME PASSWORDS"

if grep -q "syscall returned -1 (errno=13)" test08_arg2;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
else
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
fi

rm -rf test08_password test08_input test08_output test08_temp test08_arg1 test08_arg2


echo -e "=============================================================="

