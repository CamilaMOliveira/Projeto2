#include <stdio.h>

int main(void)
{
	int i;
	char nome[100];

	FILE *txt;

	/* Cria Arquivo.txt no diretorio onde o programa é executado
	caso Arquivo.txt já exista, abre com para adicionando dados
	apartir do seu fim.
	E testa se conseguiu criar ou abrir Arquivo.txt
	*/
	if((txt = fopen("/mnt/point1/Arquivo.txt", "a+")) == NULL)
	{
		perror("Descricao do erro");
		exit(1);
	}

	while(1)
	{
		printf("Digite o Nome, ou sair(para sair): ");
		fgets(nome, 100, stdin);//pega 99 caracteres da entrada padrao(teclado)
		nome[strlen(nome) - 1] = '\0';//retira o \n inserido por fgets() e finaliza a string

		// enquanto nome for diferente de sair o laço continua.
		if(strcmp("sair", nome))
		{
			fprintf(txt, "%s\n", nome);//imprime o nome, e o caracter de nova linha \n para o arquivo
		}
		else
		{
			break;//caso nome seja igual a "sair" o laço para
		}

	}


	//fecha arquivo
	fclose(txt);

	return 0;
}

