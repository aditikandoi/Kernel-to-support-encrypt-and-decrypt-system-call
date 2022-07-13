#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/slab.h>
# include <linux/uaccess.h>
# include <generated/autoconf.h>
# include <asm/unistd.h>
# include <linux/err.h>
# include <linux/scatterlist.h>
# include <linux/stat.h>
# include <linux/namei.h>
# include <linux/hash.h>
# include <linux/mm.h>
# include <linux/key-type.h>
# include <linux/ceph/decode.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <keys/ceph-type.h>
#include <crypto/internal/skcipher.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include "input_arguments.h"

char *buffer;
bool file_check = true;

#define EXTRA_CREDIT 1

asmlinkage extern long (*sysptr)(void *arg);

struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
};

static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int check_flag)
{
	int rc;

	if (check_flag == 1){
		rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req),&sk->wait);
	}
	else{
		rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req),&sk->wait);
	}
	if(rc)
		pr_info("skcipher encrypt returned with result %d\n", rc);
	return rc;
}

static int test_skcipher(unsigned char *md, int flag, int block_size, char *ivdata)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	int ret = -EFAULT;
	skcipher = crypto_alloc_skcipher("ctr(aes)", 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		ret =  PTR_ERR(skcipher);
		goto out;
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
	crypto_req_done, &sk.wait);

	if (crypto_skcipher_setkey(skcipher, md, 32)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	sk.tfm = skcipher;
	sk.req = req;

	sg_init_one(&sk.sg, buffer, block_size);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, block_size, ivdata);
	crypto_init_wait(&sk.wait);

	ret = test_skcipher_encdec(&sk, flag);
	goto out;
	// pr_info("Encryption triggered successfully\n");

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	return ret;
}

int kernel_args_validate(Arguments *kargs){
	if(!kargs){
        printk(KERN_ERR "The received arguments from the user is NULL\n");
        return -EFAULT;
    }

	if((!kargs->infile) || (!kargs->outfile)){
		printk(KERN_ERR "Input file or Output file is NULL\n");
        return -EINVAL;
	} 

	if(kargs->flag == 0){
		printk(KERN_ERR "One of the three flags (-e, -d, -c) should be used\n");
        return -EINVAL;
	}

	if((kargs->flag != 4) && ((!kargs->keybuf) || (kargs->keylen == 0))){
        printk(KERN_ERR "No password provided for encryption/decryption");
        return -EINVAL;
    }
	return 0;
}

int file_validate(struct file *input_file_open, struct file *output_file_open){
	struct inode *inode, *onode;
	inode = input_file_open->f_path.dentry->d_inode;
	onode = output_file_open->f_path.dentry->d_inode;
	if(inode == onode){
		printk(KERN_ERR "Input and outfile file node indexes are same");
		return -EINVAL;
	}

	if(!(S_ISREG(inode->i_mode) && (S_ISREG(onode->i_mode)))){
		printk(KERN_ERR "Input/Output File is not regular");
		return -EINVAL;
	}
	return 0;
}

bool copy_func(struct file *input_file_open, struct file *output_file_open, char *ivdata, int ivlen){
	ssize_t read_bytes, write_bytes;
	read_bytes = vfs_read(input_file_open, buffer, PAGE_SIZE, &(input_file_open->f_pos));
	if(read_bytes < 0){
		return false;
	}
	if(min(read_bytes, PAGE_SIZE) != PAGE_SIZE){
		write_bytes = vfs_write(output_file_open, buffer, read_bytes, &(output_file_open->f_pos));
		if(write_bytes != read_bytes)
			file_check = false;
		return false;
	}
	else{
		write_bytes = vfs_write(output_file_open, buffer, PAGE_SIZE, &(output_file_open->f_pos));
		if(write_bytes != read_bytes)
			file_check = false;
	}	 
	return true;
}

bool encr_decr_func(Arguments *kargs, struct file *input_file_open, struct file *output_file_open, char *ivdata, int ivlen){
	ssize_t read_bytes, write_bytes; 
	if(kargs->flag == 1){
		write_bytes = vfs_write(output_file_open, ivdata, ivlen, &(output_file_open->f_pos));
		if(write_bytes < 0){
			file_check = false;
			return false;
		}
	}
	else if(kargs->flag == 2){
		read_bytes = vfs_read(input_file_open, ivdata, ivlen, &(input_file_open->f_pos));

	}

	read_bytes = vfs_read(input_file_open, buffer, PAGE_SIZE, &(input_file_open->f_pos));
	if(read_bytes <= 0) {
		if(read_bytes < 0)
			file_check = false;
		return false; 
	}

	if(test_skcipher(kargs->keybuf, kargs->flag, read_bytes, ivdata) != 0){
		file_check = false;
		return false;
	}

	if(min(read_bytes, PAGE_SIZE) != PAGE_SIZE){
		write_bytes = vfs_write(output_file_open, buffer, read_bytes, &(output_file_open->f_pos));
		if(write_bytes != read_bytes)
			// printk("first write x read");
			file_check = false;
		return false;
	}
	else{
		write_bytes = vfs_write(output_file_open, buffer, PAGE_SIZE, &(output_file_open->f_pos));
		if(write_bytes != read_bytes)
			file_check = false;
	}
	return true;
}

asmlinkage long cryptocopy(void *arg)
{
	Arguments *kargs = kmalloc(sizeof(Arguments), GFP_KERNEL);
	bool flag = true;
	int validate_return;
	int validate_file;
	int write_bytes = 0;
	int return_type = 0;
	int ivlen = 16;
	struct filename *input_file, *output_file;
	struct file *input_file_open = NULL;
	struct file *temp_file_open = NULL;
	struct file *output_file_open = NULL;
	struct kstat *input_stat;
	mm_segment_t oldfs;
	ssize_t read_bytes = 0;
	char *ivdata = kmalloc(16, GFP_KERNEL);
	#ifdef EXTRA_CREDIT 
	#else
		memcpy(ivdata, "aditirajkandoi17", 16);
	#endif
	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	input_stat = kmalloc(sizeof(struct kstat), GFP_KERNEL);


	// checking if user argument struct is null
	if(!arg){
		printk(KERN_ERR "User space address is NULL\n");
		return_type = -EINVAL;
		goto argument_error;
	}

	// checking if user arguments are accessible
	if(!access_ok(arg, sizeof(Arguments))){
        printk(KERN_ERR "The user space address is invalid inside access_ok() of arg\n");
		return_type = -EFAULT;
		goto argument_error;
    }
	

	// copy_from_user(kargs, arg, sizeof(Arguments));
	if(copy_from_user(kargs, arg, sizeof(Arguments)) != 0){
		printk(KERN_ERR "Kernel space unable to copy user space address\n");
		return_type = -ENOMEM;
		goto argument_error;
	}

	// validating all kernel arguments
	validate_return = kernel_args_validate(kargs);
	if(validate_return != 0){
		return_type = validate_return;
		goto argument_error;
	}

	input_file = getname(((Arguments *) arg)->infile);
	if(IS_ERR(input_file)){
		printk(KERN_ERR "Input file is not valid\n");
		return_type = -ENOENT;
		goto argument_error;
	}
	
	output_file = getname(((Arguments *) arg)->outfile);
	if(IS_ERR(output_file)){
		printk(KERN_ERR "Output file is not valid\n");
		return_type = -ENOENT;
		goto argument_error;
	}

	if(!input_stat) {
		printk(KERN_ERR "Input stat is NULL\n");
		return_type = -ENOMEM;
		goto argument_error;
	}

	vfs_stat(kargs->infile, input_stat);
	kargs->infile = (char *)input_file->name;
	kargs->outfile = (char *)output_file->name;

	if(strcmp(kargs->infile, kargs->outfile) == 0) {
		printk(KERN_ERR "Input file and Output File are the same\n");
		// printk(KERN_ERR "Input stat is NULL\n");
		return_type = -EINVAL;
		goto argument_error;
	}

	input_file_open = filp_open(kargs->infile, O_RDONLY, 0);
	if(IS_ERR(input_file_open)) { 
		printk(KERN_ERR "File Error: input file could not be opened\n");
		return_type = -ENOENT;
		goto file_error;
	}

	output_file_open = filp_open(kargs->outfile, O_WRONLY | O_CREAT | O_TRUNC, input_stat->mode);
	if(IS_ERR(output_file_open)) {
		printk(KERN_ERR "File Error: output file could not be opened\n");
		return_type = -ENOENT;
		goto file_error;
	}

	validate_file = file_validate(input_file_open, output_file_open);
	if(validate_file != 0){
		return_type = validate_file;
		goto file_error;
	}

	char *temp_file = kargs->outfile;
	strcat(temp_file, ".tmp");

	temp_file_open = filp_open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, input_stat->mode);
	if(IS_ERR(temp_file_open)) {
		printk(KERN_ERR "File Error: temp file could not be opened\n");
		return_type = -ENOENT;
		goto file_error;
	}
	
	validate_file = file_validate(input_file_open, temp_file_open);
	if(validate_file != 0){
		return_type = validate_file;
		goto file_error;
	}

	input_file_open->f_pos = 0;
	// output_file_open->f_pos = 0;
	temp_file_open->f_pos = 0;

	oldfs = get_fs();
    set_fs(KERNEL_DS);

	if(kargs->flag == 1){
		write_bytes = vfs_write(temp_file_open, kargs->keybuf, 32, &(temp_file_open->f_pos));
		if(write_bytes <= 0){
			// file_check = false;
			return_type = -EIO;	
			goto main_error; 
		}
	}

	else if(kargs->flag == 2){
		read_bytes = vfs_read(input_file_open, buffer, 32, &(input_file_open->f_pos));
		// printk("hash bytes for decr %ld", read_bytes);
		if(read_bytes < 0){
			// file_check = false;
			goto main_error;
		}
		if(memcmp(buffer, kargs->keybuf, 32) !=0){
			return_type = -EACCES;
			printk("Can not decrypt because hash values don't match.");
			// file_check = false;
			// printk("return type: %d", return_type);
			goto main_error;
		}
	}

	while(flag){
		if(kargs->flag == 4){
			flag = copy_func(input_file_open, temp_file_open, ivdata, ivlen);
		}
		else if(kargs->flag == 1){
			#ifdef EXTRA_CREDIT
				get_random_bytes(ivdata, ivlen);
			#endif
			flag = encr_decr_func(kargs, input_file_open, temp_file_open, ivdata, ivlen);
		}
		else if(kargs->flag == 2){
			flag = encr_decr_func(kargs, input_file_open, temp_file_open, ivdata, ivlen);
		}
	}


main_error:
			if(file_check)
				vfs_rename(temp_file_open->f_path.dentry->d_parent->d_inode, temp_file_open->f_path.dentry, output_file_open->f_path.dentry->d_parent->d_inode, output_file_open->f_path.dentry, NULL, 0);
			else
				vfs_unlink(temp_file_open->f_path.dentry->d_parent->d_inode, temp_file_open->f_path.dentry, NULL);
			set_fs(oldfs);

file_error:
			if(!input_file_open)
				filp_close(input_file_open, NULL);
			if(temp_file_open != NULL)
				filp_close(temp_file_open, NULL);
			if(output_file_open != NULL)
				filp_close(output_file_open, NULL);
			
argument_error:
				kfree(kargs);
				kfree(buffer);
				kfree(ivdata);
				kfree(input_stat);
				return return_type;

}

static int __init init_sys_cryptocopy(void)
{
	printk("installed new sys_cryptocopy module\n");
	if (sysptr == NULL)
		sysptr = cryptocopy;
	return 0;
}

static void  __exit exit_sys_cryptocopy(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cryptocopy module\n");
}
module_init(init_sys_cryptocopy);
module_exit(exit_sys_cryptocopy);
MODULE_LICENSE("GPL");
