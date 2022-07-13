#!bin/bash
# Test to check if the length of the password for hashing is greater than 6 and less than 128

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "=============================================================="
echo -e "${bold}Shell Script to check if the length of password for hashing is greater than 6 and less than 128!${normal}\n"

rm -rf test01_input
touch test01_input

./xhw1 -p "dsf" -e test01_input test01_output > test01_password

echo "Testing: MINIMUM PASSWORD LENGTH"

if grep -q "INVALID PASSWORD: length of the password should be greater than 6 and less than 128." test01_password;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
rm -rf test01_password test01_input test01_output

echo -e "--------------------------------------------------------------\n"

rm -rf test01_input
touch test01_input

./xhw1 -p "kwQdV13mJLvWOpQSvCo35qxtSg1zMLfVxHpMo5qdTKR3lqlNsCesVsXQWi2IEXCbAfvEiAgwSBqIgLUGbqxtSg1zMLfVxHpMo5qdTKR3lqlNsCesVsXQWi2IEXCbAfvEiAgwSBqIgLUGbM81n6ZqNtMhKPfvnwsrIkoWpzR" -e test01_input test01_output > test01_password

echo "Testing: MAXIMUM PASSWORD LENGTH"

if grep -q "INVALID PASSWORD: length of the password should be greater than 6 and less than 128." test01_password;
then
	echo -e "${GREEN}TEST CASE 1 PASSED${NC}\n"
else
	echo -e "${RED}TEST CASE 1 FAILED${NC}\n"
fi
echo -e "=============================================================="

rm -rf test01_password test01_input test01_output