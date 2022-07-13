#!bin/bash
# Test to check if password is provided for copying the file

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if password is provided for copy!${normal}\n"

rm -rf test04_input
touch test04_input

./xhw1 -p "dsfgerg" -c test04_input test04_output > test04_password

echo "Testing: PASSWORD PROVIDED FOR COPY"

if grep -q "WARNING: Password is not required for copying the file." test04_password;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
rm -rf test04_password test04_input test04_output

echo -e "--------------------------------------------------------------\n"

rm -rf test04_input
touch test04_input

./xhw1 -c test04_input test04_output > test04_password

echo "Testing: PASSWORD NOT PROVIDED FOR COPY"
if grep -q "WARNING: Password is not required for copying the file." test04_password;
then
    echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
else
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
	
fi
echo -e "=============================================================="

rm -rf test04_password test04_input test04_output
