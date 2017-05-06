#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ksh.h"

typedef struct {
	int *pids;
	int count;
} pid_list;

typedef union {
    unsigned short is_async;
    int c;
    char *s;
    pid_list l;
} arg_t;

typedef enum {
	LIST,
	FG,
	KILL,
	WAIT,
	MEMINFO,
	MODINFO,
	HELP,
	EXIT,
} cmd_id;

typedef struct {
    const char *name;
    void (*func)(arg_t*);
    const char *args;
    const char *desc;
    const cmd_id uid;
} cmd_t;

#define MK_CMD(name) void cmd_ ## name (arg_t* args)
MK_CMD(list);
MK_CMD(fg);
MK_CMD(kill);
MK_CMD(wait);
MK_CMD(meminfo);
MK_CMD(modinfo);
MK_CMD(help);
MK_CMD(exit);

arg_t *args_parse(const char *s);

#define CMD(func, params, desc, uid) {#func, cmd_ ## func, params, desc, uid}
#define CMD_COUNT 8
cmd_t cmd_table[CMD_COUNT] ={
    CMD(list, "", "Display currently executed commands", LIST),
    CMD(fg, "<id>", "Wait for command 'id' to finish", FG),
    CMD(kill, "<signal> <pid>", "Send 'signal' to process corresponding to 'pid'", KILL),
    CMD(wait, "<pid>...", "Wait for one process specified by its 'pid' to terminate", WAIT),
    CMD(meminfo, "", "Get information concerning memory usage", MEMINFO),
    CMD(modinfo, "<module>", "Get information concerning loaded kernel 'module'", MODINFO),
    CMD(help, "", "Display this help", HELP),
    CMD(exit, "", "Exit this tool", EXIT),
};


const char *delim = " \r\n";
const char args_separator = ' ';

#define ESCAPE(str) {free(cmd_cpy); free(args); puts(str); return;}
void cmd_parse(char *cmd)
{
	int argc;
	int i;
	unsigned short is_async;
	char *async_ptr;
	arg_t *args;
	const char *tok1;
	const char *tok2;
	char *cmd_cpy, *args_ptr;

	// trim leading whitespaces
	while((*cmd) == ' ') {
		cmd++;
	}

	async_ptr = strrchr(cmd, '&');
	if(async_ptr == NULL) {
		is_async = 0;
	} else {
		is_async = 1;
		(*async_ptr) = '\0';
		// trim ending whitespaces
		while((*(--async_ptr)) == ' ') {
			(*async_ptr) = '\0';
		}
	}

	for(i = 0, argc = 0; cmd[i]; i++) {
  		argc += (cmd[i] == ' ');
	}

	cmd_cpy = (char *) malloc((strlen(cmd) + 1) * sizeof(char));
	if(cmd_cpy == NULL) {
		printf("malloc failed, exiting ...\n");
		exit(-1);
	}
	memcpy(cmd_cpy, cmd, strlen(cmd)+1);
	args_ptr = strchr(cmd_cpy, ' ') + 1;

	tok1 = strtok(cmd, delim);
   	if(!tok1 || !strlen(tok1)) {
   		free(cmd_cpy);
   		return;
   	}

	// alloc one more arg for async flag
	args = (arg_t *) malloc(sizeof(arg_t) * (argc + 1));
	if(args == NULL) {
		printf("malloc failed, exiting ...\n");
		exit(-1);
	}

	args[0].is_async = is_async;
	
	i = CMD_COUNT;
    while(i--) {
        cmd_t cur = cmd_table[i];
        if(!strcmp(tok1, cur.name)) {

        	switch(cur.uid) {
        		case LIST:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(args);
        			break;
        		case FG:
        			if(argc != 1 || (!sscanf(args_ptr, "%d", &args[1].c)))
        				ESCAPE("Bad Argument(s)");
        			cur.func(args);
        			break;
        		case KILL:
        			if(argc != 2 || (!sscanf(args_ptr, "%d %d", &args[1].c, &args[2].c)))
        				ESCAPE("Bad Argument(s)");
        			cur.func(args);
        			break;
        		case WAIT:
        			if(argc < 1)
        				ESCAPE("Bad Argument(s)");
        			args[1].l.count = argc;
        			args[1].l.pids = (int *) malloc(argc * sizeof(int));
        			if(args[1].l.pids == NULL) {
						ESCAPE("malloc failed, command aborted");
					}

        			for(int j = 0; j < argc; j++) {
        				tok2 = strtok(NULL, delim);
        				//TODO: sscanf recopie pas les valeurs des pids
        				if(tok2 == NULL || (!sscanf(tok2, "%d", &args[1].l.pids[i]))) {
        					free(args[1].l.pids);
        					ESCAPE("Bad Argument(s)");
        				}
        			}
        			cur.func(args);
        			free(args[1].l.pids);
        			break;
        		case MEMINFO:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(args);	
        			break;
        		case MODINFO:
					if(argc != 1 || (*args_ptr) == ' ' || (*args_ptr) == '\0') 
        				ESCAPE("Bad Argument(s)");
        			args[1].s = args_ptr;
        			cur.func(args);
        			break;
        		case HELP:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(args);
        			break;
        		case EXIT:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(args);
        			break;
        		default:
        			ESCAPE("Command not found");
        			break;
        	}

            free(args);
            free(cmd_cpy);
            return;
        }
    }
    ESCAPE("Command not found");
}
#undef ESCAPE

#define PROMPT "ksh> "

int main()
{
    char cmd[512];
    while(1) {
        printf("%s", PROMPT);
        fflush(stdout);
        cmd_parse(fgets(cmd, 512, stdin));
    }

    return 0;
}

void cmd_list(arg_t *args) 
{
	printf("Exec list: async=%hu\n", args[0].is_async);
}

void cmd_fg(arg_t *args)
{
	printf("Exec fg: async=%hu id=%d\n", args[0].is_async, args[1].c);
}

void cmd_kill(arg_t *args)
{
	printf("Exec kill: async=%hu signal=%d pid=%d\n", args[0].is_async, args[1].c, args[2].c);
}

void cmd_wait(arg_t *args)
{
	printf("Exec wait: async=%hu ", args[0].is_async);
	for(int i = 0; i < args[1].l.count; i++) {
		printf("pid=%d ", args[1].l.pids[i]);
	}
	printf("\n");
}

void cmd_meminfo(arg_t *args)
{
	printf("Exec meminfo: async=%hu\n", args[0].is_async);
}

void cmd_modinfo(arg_t *args)
{
	printf("Exec modinfo: async=%hu module_name=%s\n", args[0].is_async, args[1].s);
}

void cmd_exit(arg_t *args) 
{
	exit(0);
}

void cmd_help(arg_t *args)
{
    puts("Available Commands:");
    int i = CMD_COUNT;
    while(i--) {
        cmd_t cmd = cmd_table[i];
        char tmp[512];
        snprintf(tmp, 512, "%s %s", cmd.name, cmd.args);
        printf("%10s\t\t- %s\n", tmp, cmd.desc);
    }
}