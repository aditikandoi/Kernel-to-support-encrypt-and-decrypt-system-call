#!bin/bash
# Test to check if the input and outfile files are provided for encryption/decryption

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if the input and outfile files are provided for encryption/decryption!${normal}\n"

rm -rf test03_input
touch test03_input

./xhw1 -p "dsfvdvd" -e test03_input > test03_files

echo "Testing: NO OUTFILE FILE PROVIDED FOR ENCRYPTION"

if grep -q "INCORRECT SYNTAX: Mention input and output files." test03_files;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
rm -rf test03_files test03_input

echo -e "--------------------------------------------------------------\n"

rm -rf test03_input
touch test03_input

./xhw1 -p "dsfvdvd" -e test03_input test03_output > test03_files

echo "Testing: PROVIDED BOTH INPUT AND OUTPUT FILES FOR ENCRYPTION"

if grep -q "INCORRECT SYNTAX: Mention input and output files." test03_files;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
else
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
fi
echo -e "--------------------------------------------------------------\n"
rm -rf test03_files test03_input test03_output

rm -rf test03_input
touch test03_input

./xhw1 -p "dsfvdvd" -d > test03_files

echo "Testing: NOT PROVIDED BOTH INPUT AND OUTPUT FILES FOR DECRYPTION"

if grep -q "INCORRECT SYNTAX: Mention input and output files." test03_files;
then
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
        echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
	
fi
echo -e "--------------------------------------------------------------\n"
rm -rf test03_files test03_input 

rm -rf test03_input
touch test03_input

./xhw1 -p "dsfvdvd" -d  test03_input test03_output> test03_files

echo "Testing: PROVIDED BOTH INPUT AND OUTPUT FILES FOR DECRYPTION"

if grep -q "INCORRECT SYNTAX: Mention input and output files." test03_files;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
else
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
        
fi
echo -e "=============================================================="
rm -rf test03_files test03_input test03_output




