struct log_entry{
	int addr;
	int port;
	int data[30];
	void *next;
	void *prev;
};