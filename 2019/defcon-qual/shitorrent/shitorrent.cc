#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>
#include <algorithm>

/* globals */
fd_set *rfds;
int lastfd;
std::vector<int> listeners;
std::vector<int> admins;

int vhasele(std::vector<int> v, int ele) {
	if(std::find(v.begin(), v.end(), ele) != v.end()) {
		return 1; // has it
	} else {
		return 0; // doesn't have it
	}
}

void vremove(std::vector<int> v, int ele) {
	v.erase(std::remove(v.begin(), v.end(), ele), v.end());
}

void setfdlimit() {
	struct rlimit fdlimit;
	long limit;
	limit = 65536;
	fdlimit.rlim_cur = limit;
	fdlimit.rlim_max = limit;
	setrlimit(RLIMIT_NOFILE, &fdlimit);
	FD_ZERO(rfds);
}

void nobuf() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}

void intro() {
	puts("simple hybrid infrastructure torrent");
	puts("enable simple distribution of files among your fleet of machines");
	puts("used by it department the world over");
}

void printmenu() {
	puts("《SHITorrent 》management console");
	puts("[a]dd pc to manage");
	puts("[r]emove pc from fleet");
	puts("[w]ork");
	puts("[q]uit");
	puts("[g]et flag");
}

int add_node() {
	char hostname[100] = {0};
	char portstr[100] = {0};
	int port = 0;
	puts("enter host");
	read(0, hostname, 99);
	if(hostname[strlen(hostname) - 1] == '\n') {
		hostname[strlen(hostname) - 1] = '\x00';
	}
	puts("enter port");
	read(0, portstr, 99);
	port = atoi(portstr);

	struct sockaddr_in address;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char *hello = "SHITorrent HELO\n";
	char buffer[1024] = {0};
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, hostname, &serv_addr.sin_addr)<=0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}
	send(sock , hello , strlen(hello) , 0 );
	valread = read( sock , buffer, 1024);
	if (strncmp("TORADMIN", buffer, strlen("TORADMIN"))) {
		listeners.push_back(sock);
		printf("added listener node %d\n", sock);
	} else {
		admins.push_back(sock);
		FD_SET(sock, rfds);
		printf("added sending node %d\n", sock);
	}
	if (sock > lastfd) {
		lastfd = sock;
	}
	return 0;
}

void remove_node() {
	char buf[256];
	read(0, buf, 255);
	int bufno = atoi(buf);
	if (bufno > 2 && bufno <= lastfd) {
		close(bufno);
	}
	if (vhasele(listeners, bufno)) {
		vremove(listeners, bufno);
	}
	if (vhasele(admins, bufno)) {
		vremove(admins, bufno);
		if (FD_ISSET(bufno, rfds)) {
			FD_CLR(bufno, rfds);
		}
	}
}

void dispatch_it(int fd) {
	printf("dispatching from %d\n", fd);
	char *buf = (char *)calloc(1, 4096);
	int sz = read(fd, buf, 4096);
	printf("getting %s\n", buf);
	for (int i = 0; i < listeners.size(); i++) {
		write(listeners[i], buf, sz);
	}
	free(buf);
}

void workit() {
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	int retval = select(FD_SETSIZE, rfds, NULL, NULL, &tv);
	// Don't rely on the value of tv now!

	if (retval) {
		puts("DEBUG: ready to send out the data");
		// FD_ISSET(0, &rfds) will be true.
		for (int i = 3; i < lastfd; i++) {
			if (FD_ISSET(i, rfds)) {
				dispatch_it(i);
				return;
			}
		}
	} else {
		printf("no data within 5 seconds quitting");
		exit(0);
	}
}

void notmain() {
	for(;;) {
		char buf[2];
		printmenu();
		read(0, buf, 2);
		switch(buf[0]) {
			case 'a':
				{
					add_node();
				}
				break;
			case 'r':
				{
					remove_node();
				}
				break;
			case 'w':
				{
					workit();
				}
				break;
			case 'q':
				{
					return;
				}
				break;
			case 'g':
				{
					puts("lol, just kidding");
				}
				break;
			default:
				{
					puts("not supported");
				}
				break;
		}
	}
}

int main(int argc, char **argv) {
	fd_set fds;
	rfds = &fds;
	lastfd = 2;
	setfdlimit();
	nobuf();
	intro();
	notmain();
	return 0;
}
