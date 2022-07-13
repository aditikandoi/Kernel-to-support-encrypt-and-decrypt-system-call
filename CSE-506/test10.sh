#!bin/bash
# Test system call for input file that does not exist

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to test system call for input file that may or may not exist!${normal}\n"

# rm -rf test10_input, test10_output

./xhw1 -p "aditikandoi" -e test10_input test10_output > test10_arg1

echo "Testing: PROVIDING A FILE THAT DOES NOT EXIST"

if grep -q "syscall returned -1 (errno=2)" test10_arg1;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi

rm -rf test10_input test10_output test10_arg1

echo -e "--------------------------------------------------------------\n"

rm -rf test10_input, test10_output
touch test10_input 

./xhw1 -p "aditikandoi" -e test10_input test10_output > test10_arg1

echo "Testing: PROVIDING A FILE THAT EXISTS"

if grep -q "syscall returned -1 (errno=2)" test10_arg1;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n" 
else
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
fi

rm -rf test10_password test10_input test10_output test10_arg1


echo -e "=============================================================="

