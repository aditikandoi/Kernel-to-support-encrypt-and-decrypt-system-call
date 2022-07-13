#!bin/bash
# Test to check if the input and outfile files are provided for copy

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if the input and outfile files are provided for copy!${normal}\n"

rm -rf test06_input
touch test06_input

./xhw1 -c test06_input > test06_files

echo "Testing: NO OUTPUT FILE PROVIDED FOR COPY"

if grep -q "INCORRECT SYNTAX: Mention input and output files." test06_files;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
rm -rf test06_files test06_input

echo -e "--------------------------------------------------------------\n"

rm -rf test06_input
touch test06_input

./xhw1 -c > test06_files

echo "Testing: NO INPUT AND OUTPUT FILES PROVIDED FOR COPY"

if grep -q "INCORRECT SYNTAX: Mention input and output files." test06_files;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
echo -e "=============================================================="

rm -rf test06_input test06_files