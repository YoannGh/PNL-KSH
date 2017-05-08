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
    CMD(modinfo, "<module>", "Get information concerning loaded kernel 'module' (no extension)", MODINFO),
    CMD(help, "", "Display this help", HELP),
    CMD(exit, "", "Exit this tool", EXIT),
};

void handle_print_list(cmd_list_resp *list_resp);
void handle_print_kill(cmd_kill_resp *kill_resp);
void handle_print_wait(cmd_wait_resp *wait_resp);
void handle_print_meminfo(cmd_meminfo_resp *meminfo_resp);
void handle_print_modinfo(cmd_modinfo_resp *modinfo_resp);

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
	unsigned int list_size;

	cmd.is_async = args[0].is_async;

	if (ioctl(ioctl_fd, IO_LIST_SIZE, &list_size) == -1) {
		puts("ioctl list_size failed");
		return;
	}

	if(list_size == 0) {
		printf("There is currently no running commands\n");
		return;
	}
	cmd.list_args.list_size = list_size;
	cmd.list_resp.list = (cmd_list_elem *) malloc(list_size * sizeof(cmd_list_elem));

	if (ioctl(ioctl_fd, IO_LIST, &cmd) == -1) {
		puts("ioctl list failed");
		return;
	}

	if(cmd.is_async) {
		printf("Asynchronous command running with id: %lu\n", cmd.cmd_id);
		return;
	} else {
		handle_print_list(&cmd.list_resp);
	}

	free(cmd.list_resp.list);
}

void cmd_fg(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd_type;
	cmd_io_t cmd_fg;
	int list_size;

	if(args[0].is_async) {
		puts("fg command cannot run asynchronously :(");
		return;
	}

	cmd_type.is_async = args[0].is_async;
	cmd_type.fg_args.cmd_id = args[1].c;

	cmd_fg.is_async = args[0].is_async;
	cmd_fg.fg_args.cmd_id = args[1].c;

	if (ioctl(ioctl_fd, IO_FG_TYPE, &cmd_type) == -1) {
		puts("ioctl fg_type failed");
		return;
	}

	switch(cmd_type.fg_type_resp.fg_cmd_type) {
		case IO_LIST:
			if (ioctl(ioctl_fd, IO_LIST_SIZE, &list_size) == -1) {
				puts("ioctl list_size failed");
				return;
			}
			if(list_size == 0) {
				printf("There is currently no running commands\n");
				return;
			}
			cmd_fg.fg_args.cmd_id = args[1].c;

			cmd_fg.list_resp.list = (cmd_list_elem *) malloc(list_size * sizeof(cmd_list_elem));

			if (ioctl(ioctl_fd, IO_FG, &cmd_fg) == -1) {
				puts("ioctl fg failed");
				free(cmd_fg.list_resp.list);
				return;
			}

			handle_print_list(&cmd_fg.list_resp);
			free(cmd_fg.list_resp.list);
			break;
		case IO_FG:
			puts("FG received FG response, shouldnt happen");
			break;
		case IO_KILL:
			if (ioctl(ioctl_fd, IO_FG, &cmd_fg) == -1) {
				puts("ioctl fg failed");
				return;
			}
			handle_print_kill(&cmd_fg.kill_resp);
			break;
		case IO_WAIT:
			if (ioctl(ioctl_fd, IO_FG, &cmd_fg) == -1) {
				puts("ioctl fg failed");
				return;
			}
			handle_print_wait(&cmd_fg.wait_resp);
			break;
		case IO_MEM:
			if (ioctl(ioctl_fd, IO_FG, &cmd_fg) == -1) {
				puts("ioctl fg failed");
				return;
			}
			handle_print_meminfo(&cmd_fg.meminfo_resp);
			break;
		case IO_MOD:
			cmd_fg.modinfo_resp.res_buf_size = 4096;

			cmd_fg.modinfo_resp.res_buffer = (char *) 
				malloc(cmd_fg.modinfo_resp.res_buf_size * sizeof(char));

			if (ioctl(ioctl_fd, IO_FG, &cmd_fg) == -1) {
				puts("ioctl fg failed");
				return;
			}
			handle_print_modinfo(&cmd_fg.modinfo_resp);
			free(cmd_fg.modinfo_resp.res_buffer);
			break;
		case -1:
			printf("Command id %d not found\n", args[1].c);
		default:
			puts("Unknown module response");
			break;
	}
}

void cmd_kill(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;

	cmd.is_async = args[0].is_async;
	cmd.kill_args.signal = args[1].c;
	cmd.kill_args.pid = args[2].c;

	if (ioctl(ioctl_fd, IO_KILL, &cmd) == -1) {
		puts("ioctl kill failed");
		return;
	}

	if(cmd.is_async) {
		printf("Asynchronous command running with id: %lu\n", cmd.cmd_id);
		return;
	} else {
		handle_print_kill(&cmd.kill_resp);
	}
}

void cmd_wait(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;

	if(args[0].is_async) {
		puts("wait command cannot run asynchronously :(");
		return;
	}

	cmd.is_async = args[0].is_async;
	cmd.wait_args.pid_count = args[1].l.count;
	cmd.wait_args.pids = args[1].l.pids;

	if (ioctl(ioctl_fd, IO_WAIT, &cmd) == -1) {
		puts("ioctl kill failed");
		return;
	}

	handle_print_wait(&cmd.wait_resp);
}

void cmd_meminfo(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;

	cmd.is_async = args[0].is_async;

	if (ioctl(ioctl_fd, IO_MEM, &cmd) == -1) {
		puts("ioctl meminfo failed");
		return;
	}

	if(cmd.is_async) {
		printf("Asynchronous command running with id: %lu\n", cmd.cmd_id);
		return;
	} else {
		handle_print_meminfo(&cmd.meminfo_resp);
	}	
}

void cmd_modinfo(int ioctl_fd, arg_t *args)
{
	cmd_io_t cmd;
	unsigned int length;

	length = strcspn(args[1].s, " \r\n\0");
	args[1].s[length] = '\0';

	cmd.is_async = args[0].is_async;
	cmd.modinfo_args.str_len = length + 1;
	cmd.modinfo_args.str_ptr = args[1].s;

	cmd.modinfo_resp.res_buf_size = 4096;

	cmd.modinfo_resp.res_buffer = (char *) 
		malloc(cmd.modinfo_resp.res_buf_size * sizeof(char));

	if (ioctl(ioctl_fd, IO_MOD, &cmd) == -1) {
		puts("ioctl modinfo failed");
		return;
	}

	if(cmd.is_async) {
		printf("Asynchronous command running with id: %lu\n", cmd.cmd_id);
		return;
	} else {
		handle_print_modinfo(&cmd.modinfo_resp);
	}

	free(cmd.modinfo_resp.res_buffer);
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

void handle_print_list(cmd_list_resp *list_resp) {
	unsigned int i;

	for(i = 0; i < list_resp->elem_count; i++) {
		switch(list_resp->list[i].cmd_type) {
			case IO_LIST:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"LIST", list_resp->list[i].is_async);
				break;
			case IO_FG:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"FG", list_resp->list[i].is_async);
				break;
			case IO_KILL:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"KILL", list_resp->list[i].is_async);
				break;
			case IO_WAIT:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"WAIT", list_resp->list[i].is_async);
				break;
			case IO_MEM:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"MEMINFO", list_resp->list[i].is_async);
				break;
			case IO_MOD:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"MODINFO", list_resp->list[i].is_async);
				break;
			default:
				printf("Command %lu : %s Async=%hu\n", 
					list_resp->list[i].cmd_id,
					"???", list_resp->list[i].is_async);
				break;
		}
	}
}

void handle_print_kill(cmd_kill_resp *kill_resp) {
	if(kill_resp->ret == -1) {
		puts("Unknown signal argument");
	}
	else if(kill_resp->ret == -2) {
		puts("Unknown pid");
	}
	else if(kill_resp->ret < 0) {
		puts("Error sending signal to process");
	}
	else {
		puts("Successfuly sent signal to process\n");
	}
}

void handle_print_wait(cmd_wait_resp *wait_resp) {
	if(wait_resp->ret < 0) {
		printf("None of the given pid corresponds to a process\n");
	} else {
		printf("Process %d finished with an exit code of %d\n", 
			wait_resp->pid, wait_resp->exit_code);
	}
}

void handle_print_modinfo(cmd_modinfo_resp *modinfo_resp) {
	if(modinfo_resp->ret < 0) {
		printf("Module not found\n");
	} else {
		printf("%s\n", modinfo_resp->res_buffer);
	}
}

char* readable_size(unsigned long size, char *buf, int buffer_size) {
    int i = 0;
    const char* units[] = {"b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb", "Zb", "Yb"};
    while (size > 1024) {
        size /= 1024;
        i++;
    }

    if(!i) {
    	snprintf(buf, buffer_size, "0%s", units[i]);
    } else {
    	snprintf(buf, buffer_size, "%.*lu%s", i, size, units[i]);
    }
    
    return buf;
}

void handle_print_meminfo(cmd_meminfo_resp *meminfo_resp) {
	char buf[128];
	printf("sharedram: %s\n", readable_size(meminfo_resp->sharedram, &buf[0], 128));
	printf("totalram: %s\n", readable_size(meminfo_resp->totalram, &buf[0], 128));
	printf("freeram: %s\n", readable_size(meminfo_resp->freeram, &buf[0], 128));
	printf("totalhigh: %s\n", readable_size(meminfo_resp->totalhigh, &buf[0], 128));
	printf("freehigh: %s\n", readable_size(meminfo_resp->freehigh, &buf[0], 128));
	printf("bufferram: %s\n", readable_size(meminfo_resp->bufferram, &buf[0], 128));
	printf("cached: %s\n", readable_size(meminfo_resp->cached, &buf[0], 128));
	printf("totalswap: %s\n", readable_size(meminfo_resp->totalswap, &buf[0], 128));
	printf("freeswap: %s\n", readable_size(meminfo_resp->freeswap, &buf[0], 128));
}