#!bin/bash
# Test to check if password is provided for encryption/decryption

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if a password is provided for encryption/decryption!${normal}\n"

rm -rf test02_input
touch test02_input

./xhw1 -e test02_input test02_output > test02_password

echo "Testing: NO PASSWORD PROVIDED FOR ENCRYPTION"

if grep -q "INCORRECT SYNTAX: No password provided for encryption/decryption." test02_password;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
rm -rf test02_password test02_input test02_output

echo -e "--------------------------------------------------------------\n"

rm -rf test02_input
touch test02_input

./xhw1 -p "sVsXQWi2IEXCbAfvEiA" -e test02_input test02_output > test02_password

echo "Testing: PASSWORD PROVIDED FOR ENCRYPTION"

if grep -q "INCORRECT SYNTAX: No password provided for encryption/decryption." test02_password;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
else
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
	
fi
rm -rf test02_password test02_input test02_output

echo -e "--------------------------------------------------------------\n"

rm -rf test02_input
touch test02_input

./xhw1 -e test02_input test02_output > test02_password

echo "Testing: NO PASSWORD PROVIDED FOR DECRYPTION"

if grep -q "INCORRECT SYNTAX: No password provided for encryption/decryption." test02_password;
then
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
	
fi
rm -rf test02_password test02_input test02_output

echo -e "--------------------------------------------------------------\n"

rm -rf test02_input
touch test02_input

./xhw1 -p "sVsXQWi2IEXCbAfvEiA" -d test02_input test02_output > test02_password

echo "Testing: PASSWORD PROVIDED FOR DECRYPTION"

if grep -q "INCORRECT SYNTAX: No password provided for encryption/decryption." test02_password;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
else
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
	
fi

echo -e "=============================================================="

rm -rf test02_password test02_input test02_output