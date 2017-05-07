#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ksh.h"

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
	int *pids;
	int count;
} pid_list;

typedef union {
    unsigned short is_async;
    int c;
    char *s;
    pid_list l;
} arg_t;

typedef struct {
    const char *name;
    void (*func)(int ioctl_fd, arg_t*);
    const char *args;
    const char *desc;
    const cmd_id uid;
} cmd_t;

#define MK_CMD(name) void cmd_ ## name (int ioctl_fd, arg_t* args)
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
    CMD(wait, "<pid> [<pid> ...]", "Wait for one process specified by its 'pid' to terminate", WAIT),
    CMD(meminfo, "", "Get information concerning memory usage", MEMINFO),
    CMD(modinfo, "<module>", "Get information concerning loaded kernel 'module'", MODINFO),
    CMD(help, "", "Display this help", HELP),
    CMD(exit, "", "Exit this tool", EXIT),
};


const char *delim = " \r\n";
const char args_separator = ' ';

#define ESCAPE(str) {free(cmd_cpy); free(args); puts(str); return;}
void cmd_parse(int ioctl_fd, char *cmd)
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
		puts("malloc failed, exiting ...");
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
		puts("malloc failed, exiting ...");
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
        			cur.func(ioctl_fd, args);
        			break;
        		case FG:
        			if(argc != 1 || (!sscanf(args_ptr, "%d", &args[1].c)))
        				ESCAPE("Bad Argument(s)");
        			cur.func(ioctl_fd, args);
        			break;
        		case KILL:
        			if(argc != 2 || (!sscanf(args_ptr, "%d %d", &args[1].c, &args[2].c)))
        				ESCAPE("Bad Argument(s)");
        			cur.func(ioctl_fd, args);
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
        				if(tok2 == NULL || (!sscanf(tok2, "%d", &args[1].l.pids[j]))) {
        					free(args[1].l.pids);
        					ESCAPE("Bad Argument(s)");
        				}
        			}
        			cur.func(ioctl_fd, args);
        			free(args[1].l.pids);
        			break;
        		case MEMINFO:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(ioctl_fd, args);	
        			break;
        		case MODINFO:
					if(argc != 1 || (*args_ptr) == ' ' || (*args_ptr) == '\0') 
        				ESCAPE("Bad Argument(s)");
        			args[1].s = args_ptr;
        			cur.func(ioctl_fd, args);
        			break;
        		case HELP:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(ioctl_fd, args);
        			break;
        		case EXIT:
        			if(argc != 0)
        				ESCAPE("Bad Argument(s)");
        			cur.func(ioctl_fd, args);
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
    int ioctl_fd;
    char cmd[512];
	char *device_path = "/dev/ksh";

    if((ioctl_fd = open(device_path, O_RDWR)) < 0) {
    	printf("Error opening character device at %s\n", device_path);
    	perror("");
    	exit(EXIT_FAILURE);
    }

    while(1) {
        printf("%s", PROMPT);
        fflush(stdout);
        cmd_parse(ioctl_fd, fgets(cmd, 512, stdin));
    }

    close(ioctl_fd);

    return 0;
}

void cmd_list(int ioctl_fd, arg_t *args) 
{
	cmd_io_t cmd;
	printf("Exec list: async=%hu\n", args[0].is_async);

	cmd.ioctl_type = IO_LIST;
	cmd.is_async = args[0].is_async;

	if (ioctl(ioctl_fd, cmd.ioctl_type, &cmd) == -1) {
		puts("ioctl list failed");
		return;
	}

	if(cmd.is_async) {
		printf("Async Command running with id: %d\n", cmd.cmd_id);
		return;
	} else {
		//TODO: Get result
	}

}

void cmd_fg(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;
	printf("Exec fg: async=%hu id=%d\n", args[0].is_async, args[1].c);

	cmd.ioctl_type = IO_FG;
	cmd.is_async = args[0].is_async;
	cmd.fg_args.cmd_id = args[1].c;

	if (ioctl(ioctl_fd, cmd.ioctl_type, &cmd) == -1) {
		puts("ioctl fg failed");
		return;
	}

	if(cmd.is_async) {
		printf("Async Command running with id: %d\n", cmd.cmd_id);
		return;
	} else {
		//TODO: Get result
	}
}

void cmd_kill(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;
	printf("Exec kill: async=%hu signal=%d pid=%d\n", args[0].is_async, args[1].c, args[2].c);

	cmd.ioctl_type = IO_KILL;
	cmd.is_async = args[0].is_async;
	cmd.kill_args.signal = args[1].c;
	cmd.kill_args.pid = args[2].c;

	if (ioctl(ioctl_fd, cmd.ioctl_type, &cmd) == -1) {
		puts("ioctl kill failed");
		return;
	}

	if(cmd.is_async) {
		printf("Async Command running with id: %d\n", cmd.cmd_id);
		return;
	} else {
		if(cmd.kill_resp.ret == -1) {
			puts("Unknown signal argument");
		}
		else if(cmd.kill_resp.ret == -2) {
			printf("Process with pid %d not found\n", cmd.kill_args.pid);
		}
		else if(cmd.kill_resp.ret < 0) {
			printf("Error sending signal %d to pid %d\n",cmd.kill_args.signal, cmd.kill_args.pid);
		}
		else {
			printf("Successfuly sent signal %d to pid %d\n",cmd.kill_args.signal, cmd.kill_args.pid);
		}
	}
}

void cmd_wait(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;
	printf("Exec wait: async=%hu ", args[0].is_async);
	for(int i = 0; i < args[1].l.count; i++) {
		printf("pid=%d ", args[1].l.pids[i]);
	}
	printf("\n");

	cmd.ioctl_type = IO_WAIT;
	cmd.is_async = args[0].is_async;
	cmd.wait_args.pid_count = args[1].l.count;
	cmd.wait_args.pids = args[1].l.pids;

	if (ioctl(ioctl_fd, cmd.ioctl_type, &cmd) == -1) {
		puts("ioctl kill failed");
		return;
	}

	if(cmd.is_async) {
		printf("Async Command running with id: %d\n", cmd.cmd_id);
		return;
	} else {
		//TODO: Get result
	}
}

void cmd_meminfo(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;
	printf("Exec meminfo: async=%hu\n", args[0].is_async);

	cmd.ioctl_type = IO_MEM;
	cmd.is_async = args[0].is_async;

	if (ioctl(ioctl_fd, cmd.ioctl_type, &cmd) == -1) {
		puts("ioctl meminfo failed");
		return;
	}

	if(cmd.is_async) {
		printf("Async Command running with id: %d\n", cmd.cmd_id);
		return;
	} else {
		//TODO: Get result
	}
}

void cmd_modinfo(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;
	unsigned int length;
	printf("Exec modinfo: async=%hu module_name=%s\n", args[0].is_async, args[1].s);

	length = strcspn(args[1].s, " \0");
	args[1].s[length] = '\0';

	cmd.ioctl_type = IO_MOD;
	cmd.is_async = args[0].is_async;
	cmd.modinfo_args.str_len = length + 1;
	cmd.modinfo_args.str_ptr = args[1].s;

	if (ioctl(ioctl_fd, cmd.ioctl_type, &cmd) == -1) {
		puts("ioctl modinfo failed");
		return;
	}

	if(cmd.is_async) {
		printf("Async Command running with id: %d\n", cmd.cmd_id);
		return;
	} else {
		//TODO: Get result
	}
}

void cmd_exit(int ioctl_fd, arg_t *args) 
{
	exit(EXIT_SUCCESS);
}

void cmd_help(int ioctl_fd, arg_t *args)
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