#include <stdio.h>

int main(void)
{
	char url[]="/mnt/point1/Arquivo.txt";
	char ch;
	FILE *arq;
	
	arq = fopen(url, "r");
	if(arq == NULL)
	    printf("Erro, nao foi possivel abrir o arquivo\n");
	else
	    while( (ch=fgetc(arq))!= EOF )
		putchar(ch);
			
	fclose(arq);
	
	return 0;
}

