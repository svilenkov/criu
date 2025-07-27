#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <../../include/debug.h>

int main(int argc, char **argv)
{
    int i;
    FILE *log = fopen("victim.log", "w");
    if (!log) {
        perror("fopen victim.log");
        return 1;
    }

    print_stack_info_fp(log, "INSIDE victim");
	while (1) {
		if (read(0, &i, sizeof(i)) != sizeof(i))
			break;

		if (write(1, &i, sizeof(i)) != sizeof(i))
			break;
	}

	return 0;
}
