#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <errno.h>
#include<unistd.h>
#include<stdbool.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <openssl/md5.h>
#include<openssl/evp.h>

#ifndef __NR_cryptocopy
#error cryptocopy system call not defined
#endif

#define MAX_FILE_PATH_LEN 500

#include "input_arguments.h"

int is_fileValid(char *fileName, bool input_output){
    if(access(fileName, F_OK)){
       // printf("File does not exist\n");
        return -ENOENT;
    }

    if(input_output == 1){
        if(access(fileName, R_OK)){
       // printf("Input file does not have read permission\n");
        return -EPERM;
        }
    }
    else{
        if(access(fileName, W_OK)){
       // printf("Output file does not have write permission\n");
        return -EPERM;
        }
    }

    struct stat fileName_stat;
    stat(fileName, &fileName_stat);
    if(!S_ISREG(fileName_stat.st_mode)){
       // printf("It is not a regular file\n");
        return -EFAULT;
    } 
    return 0;
}

unsigned char *getMd5Hash(char *password, size_t pass_length, unsigned char *keybuf, char *hash) { 
    unsigned int hash_value_length = 0;
    // char *hash = (char *) malloc(32);
    EVP_MD_CTX *ctx = NULL; 
    const EVP_MD *mdType = EVP_md5();      
    ctx = EVP_MD_CTX_create(); 
     
    EVP_MD_CTX_init(ctx); 
    EVP_DigestInit_ex(ctx, mdType, NULL); 
    EVP_DigestUpdate(ctx, password, pass_length); 
    EVP_DigestFinal_ex(ctx, keybuf, &hash_value_length);

    for(int i = 0; i < hash_value_length; i++){
        // printf("%02x\n", keybuf[i]);
        sprintf(&hash[i*2], "%02x", keybuf[i]);
    }
    // printf("\n");
    // printf("%s", hash);
    return hash; 
}

bool passwordCheck(int length){
    if(length < 6 || length > 128){
        printf("INVALID PASSWORD: length of the password should be greater than 6 and less than 128.\n");
        return true;
    }
    return false;
}

bool encryDecryCopyCheck(int flag){
    if(flag != 0){
        printf("INCORRECT SYNTAX: One of the three flags (-e, -d, -c) should be used. Use -h for help.\n");
        return true;
    }
    return false;
}

void help(){
    printf("HELP USAGE MESSAGES\n");
    printf("Following are the tasks performed by the system call (with arguments specified\n");
    printf("1. ENCRYPTION:\n");
    printf("./test_cryptocopy -p password - e inputfile outputfile\n");
    printf("1. DECRYPTION:\n");
    printf("./test_cryptocopy -p password -d inputfile outputfile\n");
    printf("1. COPY:\n");
    printf("./test_cryptocopy -c inputfile outputfile\n");
}

void argument_check(int option){
    if(option == 'p')
        printf("Password requires one argument\n");
}

int main(int argc, char *argv[]){
    Arguments *args = (Arguments *) malloc(sizeof(Arguments));
    // unsigned char *hash;
    char *hash = (char *) malloc(32);
    int rc = 1;
	void *dummy = (void *) args;
    args->flag = 0;
    args->infile = (char *) malloc(sizeof(char) * MAX_FILE_PATH_LEN);
    args->outfile = (char *) malloc(sizeof(char) * MAX_FILE_PATH_LEN);
    args->keybuf = malloc(sizeof(char));
    int command_flag_char;
    int input_pwd = 0;
    char *password;
    int r_value = 0;
    
    if(argc == 1){
        help();
        goto end;
        // exit(0);
    }

    while((command_flag_char = getopt(argc, argv, "p:edch")) != -1){
        switch(command_flag_char){
            case 'p':
                    input_pwd = 1;
                    //passwordCheck(strlen(optarg));
                    if(passwordCheck(strlen(optarg))){
                        goto end;
                    }
                    //args->keybuf = optarg;
                    hash = getMd5Hash(optarg, strlen(optarg), args->keybuf, hash);
                    args->keylen = strlen(hash);
                    strcpy(args->keybuf, hash);
                    // printf("\n%s", args->keybuf);
                    // args->keylen = strlen(hash); 
                    break;
            case 'e':
                    if(encryDecryCopyCheck(args->flag)){
                        goto end;
                    }
                    args->flag = 1;
                    break;
            case 'd':
                    if(encryDecryCopyCheck(args->flag)){
                        goto end;
                    }
                    args->flag = 2;
                    break;
            case 'c':
                    if(encryDecryCopyCheck(args->flag)){
                        goto end;
                    }
                    args->flag = 4;
                    break;
            case 'h':
                    help();
                    goto end;
            case '?':
                    argument_check(command_flag_char);
                    goto end;
            default:
                    printf("INCORRECT SYNTAX: use -h for help.\n");
                    goto end;
        }

    }

    if((args->flag == 1 || args->flag == 2) && input_pwd == 0){
        printf("INCORRECT SYNTAX: No password provided for encryption/decryption. Use -h for help.\n");
        goto end;
    }

    if(args->flag == 4 && input_pwd == 1){
        printf("WARNING: Password is not required for copying the file.\n");
    }

    if(!(args->flag == 1 || args->flag == 2 || args->flag == 4)){
        printf("INCORRECT SYNTAX: One of the three flags (-e, -d, -c) should be used. Use -h for help.\n");
        goto end;
    }

    if((args->flag != 0 && input_pwd == 1 && argc != 6) || (args->flag == 4 && input_pwd == 0 && argc != 4)){
        // printf("%d %d", args->flag, argc);
        printf("INCORRECT SYNTAX: Mention input and output files. Use -h for help.\n");
        goto end;
    }


    if(args->keylen == 0 && input_pwd == 1){
        printf("HASH FUNCTION ERROR: Error generating the hash value.\n");
        goto end;
    }
    strcpy(args->infile, argv[optind]);
    strcpy(args->outfile, argv[optind+1]);
    
    if(!args->infile || !args->outfile){
        printf("FILE ERROR: File points to NULL.\n");
        goto end;
    }
  	rc = syscall(__NR_cryptocopy, dummy);
	if (rc == 0)
		printf("\nsyscall returned %d\n", rc);
	else
		printf("\nsyscall returned %d (errno=%d)\n", rc, errno);



end:
    if(!hash)
        free(hash);
    if(!args->infile)
        free(args->infile);
    if(!args->outfile)
        free(args->outfile);
    if(!args->keybuf)
        free(args->keybuf);
    if(!args)
        free(args);
    exit(rc);
}
