#include <stdio.h>
int main(int argc, char** argv)
{
	FILE* fp;
	char readbuf[0x24];
	memset(readbuf, 0, 0x30);
	fp = fopen("dia3url", "r");
	fgets(readbuf, 0x30, fp);

	printf("Download Dia3 at here : %s\n", readbuf);
	fgets(readbuf, 0x30, fp);
	printf("Description : %s\n", readbuf);
	
}
