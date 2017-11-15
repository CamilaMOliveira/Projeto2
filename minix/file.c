/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

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
ssize_t cipher_file_read_iter(struct kiocb *iocb, struct iov_iter *iter);
void encrypt(char *buf);
void decrypt(char *buf);

char *vetor[2];
static char* key = "limao";
#define AES_BLOCK_SIZE 16

/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
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
	ssize_t result;
	char *buf = kmalloc (sizeof (char) * 256,GFP_KERNEL);
	struct iov_iter copia;
	int len;
	buf = "encriptado"; //Estah com esse valor apenas para testar

	printk("DADOS ================ %s ==========\n",from->iov->iov_base);//mostra os dados que o usuario escreveu. (antes de serem cifrados)

	printk("BUF =========== %s",buf); //printa "encriptado"


	/* CHAMAR A FUNCAO DE ENCRIPTAR AQUI E ATUALIZAR BUF COM ELE
	
	dado_encriptado = encrypt(from->iov->iov_base);	

	buf = dado_encriptado;

	*/

	len = strlen(buf);
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len }; //Coloca o dado encriptado (buf) e seu tamanho na iovec

	iov_iter_init(&copia, WRITE, &iov, 1, len); //Inicializa a nova struct com os dados de iovec (que serao escritos no arquivo no lugar do dado original)

	printk("COPIA =========== %s",copia.iov->iov_base); //printa o que serah escrito no arquivo -> Os dados cifrados

	result = generic_file_write_iter(iocb, &copia); //escreve no arquivo os dados cifrados



	return result;
}

/*ssize_t cipher_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t result;
	char *buf = kmalloc (sizeof (char) * 256,GFP_KERNEL);

	struct iov_iter struct_decifrada;
        int len;

	buf = "decifrado";

	printk("--------------- PASSOU POR CIPHER READ ITERRRRRRRRRRRR \n");

	result = generic_file_read_iter(iocb, iter);
	printk("--------------- DADO LIDO ===> %s",iter->iov->iov_base);

	len = strlen(buf);
        struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };

        iov_iter_init(&struct_decifrada, WRITE, &iov, 1, len);

        printk("DADO DECIFRADO =========== %s",struct_decifrada.iov->iov_base);

        result = generic_file_write_iter(iocb, &struct_decifrada);

	return result;
} */

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


const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
