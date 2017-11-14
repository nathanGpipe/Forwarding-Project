#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct table_entry {
	char* prefix;
    char* nexthop;
    char interface[8];
};

int main(int argc, char** argv) {
	
	char* filename = "r1-table.txt";
	char* target_ip = argv[1];
	
	
	FILE* fp = fopen(filename, "r");
	struct table_entry ip_table[6];
	char line_string[50];
	char* line = NULL;
	char* rTable = "";
	size_t len = 0;
	size_t read;

	int i = 0;
	while((read = getline(&line, &len, fp)) != -1) {
		printf("%s\n", line);
		strcpy(line_string, line);

        line_string[read] = '\0';
		printf("1\n");
        strcpy(ip_table[i].prefix, strtok(line_string, " "));
		printf("2\n");
        strcpy(ip_table[i].nexthop, strtok(NULL, " "));
		printf("3\n");
        strcpy(ip_table[i].interface, strtok(NULL, "\n"));
		
		printf("%s %s %s\n",ip_table[i].prefix, ip_table[i].nexthop, ip_table[i].interface);
		
		i++;
	}

	for(i = 0; i < 6; i++) {
		int length;
		char* prefix_len;
		char* prefix_def;

		printf("1\n");
		prefix_def = strtok(ip_table[i].prefix, "/");
		printf("2\n");
		prefix_len = strtok(NULL, " ");
		length = (atoi(prefix_len))/8;
	}
	
	free(line);
	fclose(fp);

}
