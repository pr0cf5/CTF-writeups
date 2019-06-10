#include <stdio.h>
#include <stddef.h>

int main(){
	printf("struct size: %d\n",sizeof(struct _IO_FILE));
	printf("offset of lock: %d\n",offsetof(struct _IO_FILE, _lock));
	printf("_IO_CURRENTLY_PUTTING: %x\n",_IO_CURRENTLY_PUTTING);
	printf("_IO_IN_BACKUP: %x\n",_IO_IN_BACKUP);
	return 0;
}
