#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv, char **envp){
	if(argc!=2){
		printf("usage: ./pack <number>\n");
		exit(-1);

	}
	char * end_ptr;
	unsigned long x = strtoull(argv[1],&end_ptr,10);
	double y = *(double *)(&x);
	printf("%.1000g\n",y);
	return 0;
}
