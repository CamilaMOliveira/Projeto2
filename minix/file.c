/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
//#include <stdio.h>

#include "minix.h"
#include <linux/uio.h>
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

ssize_t cipher_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
ssize_t decipher_file_read_iter(struct kiocb *iocb, struct iov_iter *iter);
void encrypt(char *buf);
void decrypt(char *buf);

char *vetor[2];
char *dest1;
static char* key;
#define AES_BLOCK_SIZE 16

module_param(key, charp, 0000);

/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= decipher_file_read_iter, //generic_file_read_iter,
	.write_iter	= cipher_file_write_iter, //generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};



static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	printk("@@@ minix_setattr em file.c \n");

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}


ssize_t cipher_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t result_cipher;
	struct iov_iter copia;
	int len;

	printk("DADOS ================ %s ==========\n",from->iov->iov_base);//mostra os dados que o usuario escreveu. (antes de serem cifrados)

	printk("key -------------%s", key);


	encrypt(from->iov->iov_base);
	

	len = strlen(vetor[1]);
	struct iovec iov = { .iov_base = (void __user *)vetor[1], .iov_len = len }; //Coloca o dado encriptado (buf) e seu tamanho na iovec

	iov_iter_init(&copia, WRITE, &iov, 1, len); //Inicializa a nova struct com os dados de iovec (que serao escritos no arquivo no lugar do dado original)

	printk("COPIA =========== %s",copia.iov->iov_base); //printa o que serah escrito no arquivo -> Os dados cifrados

	result_cipher = generic_file_write_iter(iocb, &copia); //escreve no arquivo os dados cifrados


	return result_cipher;
}

ssize_t decipher_file_read_iter(struct kiocb *iocb, struct iov_iter *from) {

	ssize_t result_decipher, result;
	struct iov_iter copia_decipher;
	int len_decipher;

	result_decipher = generic_file_read_iter(iocb, from); //Le do arquivo os dados cifrados

	printk("@@@ DADO LIDO QUE SERAH DECIFRADO ============ %s \n",from->iov->iov_base);

	printk("key---- decypher ------%s\n", key);

	decrypt(from->iov->iov_base);

	printk("dados decifrados -------%s\n", dest1);

	len_decipher = strlen(dest1);

	memset(from->iov->iov_base, 0, strlen(from->iov->iov_base)); //Zera o campo que recebera o dado decifrado

	memcpy(from->iov->iov_base,dest1,len_decipher);	//Substitui pelo dado decifrado

	return result_decipher;
}


void encrypt(char *buf)  
{     
    char *buf1 = kmalloc (sizeof (char) * 256,GFP_KERNEL);
    char *buf2 = kmalloc (sizeof (char) * 256,GFP_KERNEL);

    int w=0, j=0;
    char* dest;
 
    printk("buf: %s", buf);
    dest= buf1;
    struct crypto_cipher *tfm;  
    int i,count,div=0,modd;  
    div=strlen(buf)/AES_BLOCK_SIZE;  
    modd=strlen(buf)%AES_BLOCK_SIZE; 
    printk("MOD: %i", modd); 
    if(modd>0)  
        div++; 
    printk("DIV: %i", div); 
    count=div;  
    tfm=crypto_alloc_cipher("aes", 0, 16); 
    printk("POS CRYPTO");   
    crypto_cipher_setkey(tfm,key,16);    
    printk("CRYPTO CIPHER SETKEY");
    for(i=0;i<count;i++)  
    {  
	printk("ENTROU FOR");
        crypto_cipher_encrypt_one(tfm,dest,buf);
        printk("vez FOR: %i", i);      
        buf=buf+AES_BLOCK_SIZE;  
    }
    printk("POS FOR");
    crypto_free_cipher(tfm); 

    printk("Cifrado sem hexa: %s", dest); 

    
    for(w=0,j=0; w<strlen(dest); w++,j+=2)
    {
	sprintf((char *)buf2+j,"%02x",dest[w]);

    }

    buf2[j] = '\0';
    
    vetor[0] = dest;
    vetor[1] = buf2;

    printk("Teste vetor %s  %s ", vetor[0], vetor[1]);
    printk("Cifrado em Hexa: %s", buf2);

}

void decrypt(char *buf)
{
	    char *buf1 = kmalloc (sizeof (char) * 256,GFP_KERNEL);

	    dest1 = buf1;


	    struct crypto_cipher *tfm;
	    int i,count,div,modd;
	    div=strlen(buf)/AES_BLOCK_SIZE;
	    modd=strlen(buf)%AES_BLOCK_SIZE;
	    if(modd>0)
		div++;
	    count=div;


	    tfm=crypto_alloc_cipher("aes", 0, 16);
	    crypto_cipher_setkey(tfm,key,16);
	    for(i=0;i<count;i++)
	    {
		crypto_cipher_decrypt_one(tfm,dest1,vetor[0]);
		buf=buf+AES_BLOCK_SIZE;
	    }


	    printk("Decifrado: %s", dest1);
}


const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
