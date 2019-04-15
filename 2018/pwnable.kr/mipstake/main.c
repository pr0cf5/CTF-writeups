/*references: http://logos.cs.uic.edu/366/notes/mips%20quick%20tutorial.htm
http://www.mrc.uidaho.edu/mrc/people/jff/digital/MIPSir.html
*/
int globvar//0x419140

void map_memory(){// sub_400988
	mmap(0x66666000,0x2000,3,0x802,0,0);
} 

void my_recv(int fd,char *buf, size_t len){
	/*
	pretty obvious i guess?
	*/
}

void handle_client(int clifd){
	char buf[??]; //0x18
	void *retaddr; //0x4
	my_recv(clifd,buf,0x2000);
}

int main(int argc, char **argv){
	char buf[0x10];
	var_38 = globvar;
	strand(time(NULL));
	map_memory();
	memset(buf,0,0x10);
	struct sockaddr_in addr;
	int clifd,fd

	addr.sin_port = htons(9033);
	addr.sin_addr = 0;

	fd = socket(AF_INET,SOCK_DGRAM,0);
	if(bind(fd,&addr,0x10)<0){
		puts("bind error");
		return 0;
	}

	listen(5);

	puts("no need to brute-force..");
	sleep(1);

	puts("listening...");

	if((clifd = accpet(fd,NULL,NULL))<0){
		perror("[X] accept");
	}

	printf("got client %d\n",clifd);

	if(!fork()){
		alarm(0x3C);
		handle_client(clifd);
		printf("client %d exit normally\n",clifd);
	}
	else{
		/*
		reverse engineer loc_400CE4 to figure it out
		*/
	}


}