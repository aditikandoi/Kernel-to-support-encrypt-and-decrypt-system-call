#!bin/bash
# Test to check if multiple flags are provided in the command line

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if multiple flags are provided in the command line!${normal}\n"

rm -rf test05_input
touch test05_input

./xhw1 -p "dsfvdvd" -e test05_input -d test05_output > test05_files

echo "Testing: ENCRYPTION AND DECRYPTION IN THE SAME COMMAND"

if grep -q "INCORRECT SYNTAX: One of the three flags (-e, -d, -c) should be used." test05_files;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
rm -rf test05_files test05_input test05_output

echo -e "--------------------------------------------------------------\n"

rm -rf test05_input
touch test05_input

./xhw1 -p "dsfvdvd" -e -c test05_input test05_output > test05_files

echo "Testing: ENCRYPTION AND COPY IN THE SAME COMMAND"

if grep -q "INCORRECT SYNTAX: One of the three flags (-e, -d, -c) should be used." test05_files;
then
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"

fi
echo -e "--------------------------------------------------------------\n"
rm -rf test05_files test05_input test05_output

rm -rf test05_input
touch test05_input

./xhw1 -p "dsfvdvd" -c test05_input test05_output -d > test05_files

echo "Testing: DECRYPTION AND COPY IN THE SAME COMMAND"

if grep -q "INCORRECT SYNTAX: One of the three flags (-e, -d, -c) should be used." test05_files;
then
    echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
        echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
	
fi

echo -e "=============================================================="
rm -rf test05_files test05_input test05_output




