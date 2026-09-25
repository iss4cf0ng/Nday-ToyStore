// vulnerable.c

#include <stdio.h>
#include <stdlib.h>

/* run this program using the console pauser or add your own getch, system("pause") or input loop */

void do_something(FILE *pfile)
{
	char buf[128];
	fscanf(pfile, "%s", buf);
	
	// do file reading and parsing below
	// ...
}

int main(int argc, char *argv[]) {
	char dummy[1024];
	FILE *pfile;
	
	printf("Vulnerable001 starts...\n");
	
	if (argc >= 2)
		pfile = fopen(argv[1], "r");
	if (pfile != NULL)
		do_something(pfile);
		
	printf("Vulnerable001 ends...\n");
	
	return 0;
}