## AIM
To develop a Linux kernel that supports dynamic system calls with three basic operations that are encryption (-e), decryption (-d), and copy (-c) and write shell scripts to test the program.


## REQUIREMENTS

* The system call sys_crytocopy() is implemented in Linux vanilla 5.X, which compiles the user and the kernel module code.
  
* The system requires installing OpenSSL libraries for MD5 hashing.

* Valid Input file to encrypt, decrypt and copy the data.



## FILES

- /usr/src/hw1-akandoi/CSE-506/README.md
- /usr/src/hw1-akandoi/CSE-506/input_arguments.h
- /usr/src/hw1-akandoi/CSE-506/xhw1.c
- /usr/src/hw1-akandoi/CSE-506/sys_cryptocopy.c
- /usr/src/hw1-akandoi/CSE-506/run_shell_scripts
- /usr/src/hw1-akandoi/CSE-506/MakeFile
- /usr/src/hw1-akandoi/CSE-506/kernel.config


## SYSTEM DESIGN
##### A. USER MODULE (xhw1.c)

This is a user-level file where the user passes the password, input file, and output file, and it requests the system call to encrypt, decrypt, or copy a file.

The valid commands by a user are:
        * ./xhw1 -p password -c input_file output_file
        * ./xhw1 -p password -e input_file output_file
        * ./xhw1 -p password -d input_file output_file


1. The user parameters are taken from the command line arguments, and the getopt command is used to parse the input.

        ./xhw1 -p password -{e/d/c} infile outfile
        
        -p: enter a password
        -e: encrypt input file and write to the output
        -d: decrypt input file and write to the output
        -c: copy input file to the output
          
        For Help - ./xhw1 -h 

2. The program performs several checks on the sequence of the arguments, and the arguments itself. The valid parameter checks are as follows:
* The password length provided by the user (if it is more than 6 and less than 128). If yes, it is hashed using the MD5 algorithm and stored in the keybuff field of the struct.
* If multiple flag have been provided by the user.
* For encryption and decryption, if the password is provided by the user.
* For encryption and decryption, if the number of arguments constants is 6 and incase of copy, the number of arguments constants is 4.
* No flag is passed.
* No input/output files provided.
* If the length of the hash value generated for a given password is zero.

3. The user invoked a system call provided all the above checks are valid. Now, the arguments are passed to the kernel space using the below defined struct -
    
      **sys_crytocopy(Arguments)**

        typedef struct{
            char *infile; 
            char *outfile; 
            unsigned char *keybuff; 
            int keylen; 
            int flag; 
        } Arguments;

  where,

  infile : the name of an input file to encrypt or decrypt, 
  
  outfile : the output file
  
  keybuff : a buffer holding the cipher key
  
  keylen : is the length of that buffer
  
  flags : determines whether to perform encryption or decryption 


| Flags | Description |
| :---  |    :----:   | 
| 1   | encrypt the infile onto the outfile |
| 2   | decrypt the infile onto the outfile | 
| 4   | copy the infile to the outfile  | 
 

##### B. KERNEL MODULE (sys_cryptocopy.c)

1. The program checks if the user space arguments are accessible or NULL. If so, it exits the function and returns an error value.

2. The program then copies the parameters from the user via a function - **copy_from_user**. Once the kernel copies all the parameters from the user module it validates all the arguments using the defined function in the system call - **kernel_args_validate**.

3. The program opens the input and output files via a function - **filp_open**, then it performs various checks using the defined function - **file_validate**. If the files pass all the checks, a "temp" file is created in the program which is the identical to the output file with an extension **".tmp"**. All the writes take place in this file.

3. The program then checks if the user wants to copy, encrypt or decrypt a file. 
* For encryption, the hashed key and the randomly generated IV data (for each block) is added to the preamble of the output file. Then, the function **encr_decr_func** is called which encrypts the data in blocks(PAGE_SIZE) using the function **test_skcipher** until the end of file or error. 
* For decryption, the key is extracted from the preamble of the input file. Similar to encryption, the function **encr_decr_func** is called which decrypts the data in blocks(PAGE_SIZE) using the function **test_skcipher** until the end of file or error. 
* For copy, the defined function **copy_func** is called which reads and writes the data in blocks(PAGE_SIZE) until the end of file or error.

4. If the data is encrypted/decrypted/copied successfully, the content is passed from the partially created ".tmp" file to the output file. While if it is unsuccessfully, the file is deleted.

5. Errors during the program are notified back to the user using the error commands -
  * -EFAULT (invalid memory address)
  * -ENOMEM (cannot allocate memory)
  * -EINVAL (invalid parameters)
  * -EPERM (permission denied)
  * -EACCES (invalid access)
  * -ENOENT (invalid file or directory)


## TEST CASES

  * test01.sh - Test to check if the length of the password for hashing is greater than 6 and less than 128
  * test02.sh - Test to check if password is provided for encryption/decryption
  * test03.sh - Test to check if the input and outfile files are provided for encryption/decryption
  * test04.sh - Test to check if password is provided for copying the file
  * test05.sh - Test to check if multiple flags are provided in the command line
  * test06.sh - Test to check if the input and outfile files are provided for copy
  * test07.sh - Test system calls if input file and outfile file are same for encryption/decryption/copy
  * test08.sh - Test system call for different passwords
  * test09.sh - Test system call for different sizes of input file
  * test10.sh - Test system call for input file that does not exist
 
    To run the test cases, use 'sh run_shell_scripts" on command line. This will run all the tests.


## REFERENCES
  * https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/
  * https://www.kernel.org/doc/html/v4.18/crypto/api-samples.html
  * https://stackoverflow.com/questions/1184274/read-write-files-within-a-linux-kernel-module
  * https://elinux.org/Debugging_by_printing
  * https://docs.google.com/document/d/1SZzhy36R6oHlEzg-kZLoSInbpQpxhbEzoHUnpi6YiUM
  * https://stackoverflow.com/questions/15621764/generate-a-random-byte-stream
  * https://www.kernel.org/doc/html/v4.18/filesystems/fscrypt.html
  * https://stackoverflow.com/questions/31083312/linux-kernel-vfs-stat-function-does-not-return-device-id-of-the-file
  * https://www.linuxjournal.com/article/8110
  * https://elixir.bootlin.com/linux/latest/source/include/linux/fs.h
  * https://stackoverflow.com/questions/24290273/check-if-input-file-is-a-valid-file-in-c
  * https://lwn.net/Articles/721305/
  * https://stackoverflow.com/questions/37897767/error-handling-checking-in-the-kernel-realm
  * https://elixir.bootlin.com/linux/latest/source/Documentation/crypto/api-intro.txt
  * https://www.kernel.org/doc/htmldocs/filesystems/API-vfs-unlink.html
