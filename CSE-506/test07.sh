#!bin/bash
# Test system calls if input file and outfile file are same for encryption/decryption/copy

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if the input and outfile files are same for encryption/decryption/copy!${normal}\n"

rm -rf test07_input
touch test07_input

./xhw1 -c test07_input test07_input > test07_password

echo "Testing: SAME INPUT AND OUTPUT FILES FOR COPY"

if grep -q "syscall returned -1 (errno=22)" test07_password;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi

rm -rf test07_password test07_input

echo -e "--------------------------------------------------------------\n"

rm -rf test07_input
touch test07_input

./xhw1 -p "aditikandoi" -e test07_input test07_input > test07_password

echo "Testing: SAME INPUT AND OUTPUT FILES FOR ENCRYPTION"
if grep -q "syscall returned -1 (errno=22)" test07_password;
then
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
	
fi
rm -rf test07_password test07_input

echo -e "--------------------------------------------------------------\n"

rm -rf test07_input
touch test07_input

./xhw1 -p "aditikandoi" -d test07_input test07_output > test07_password

echo "Testing: DIFFERENT INPUT AND OUTPUT FILES FOR DECRYPTION"
if grep -q "syscall returned -1 (errno=22)" test07_password;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
    
else
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
	
fi
rm -rf test07_password test07_input test07_output


echo -e "=============================================================="

