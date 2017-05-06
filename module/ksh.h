#ifndef KSH_H
#define KSH_H

/* Params IN */

typedef struct  {
	unsigned long cmd_id;
} cmd_fg_args;

typedef struct {
	int signal;
	int pid;
} cmd_kill_args;

typedef struct {
	int *pids;
	unsigned int pid_count;
} cmd_wait_args;

typedef struct {
	char *str_ptr;
	unsigned int str_length;
} cmd_modinfo_args;

/* Params OUT */

typedef struct {
	unsigned int list_size;
} cmd_list_resp;

typedef struct {
	int pid;
	int ret_value;
} cmd_wait_resp;

typedef struct {
	unsigned long total;
	unsigned long free;
	unsigned long used;
} cmd_meminfo_resp;

typedef struct {
	unsigned int module_name_length;
	char *module_name;
	unsigned long version;
	unsigned long mapped_addr;
} cmd_modinfo_resp;

typedef union {
	cmd_list_resp list_resp;
	cmd_wait_resp wait_resp;
	cmd_meminfo_resp meminfo_resp;
	cmd_modinfo_resp modinfo_resp;
} cmd_fg_resp;

/* cmd_io_t: struct for communication between user and kernel space */

typedef struct {
	int ioctl_type;
	union {
		cmd_fg_args fg_args;
		cmd_kill_args kill_args;
		cmd_wait_args wait_args;
		cmd_modinfo_args modinfo_args;
	};
	union {
		cmd_list_resp list_resp;
		cmd_wait_resp wait_resp;
		cmd_meminfo_resp meminfo_resp;
		cmd_modinfo_resp modinfo_resp;
		int cmd_id;
	};
} cmd_io_t;

#define IO_MAGICNUMBER 'N'

#define IO_LIST _IOWR(IO_MAGICNUMBER, 1, cmd_io_t)
#define IO_FG _IOWR(IO_MAGICNUMBER, 2, cmd_io_t)
#define IO_KILL _IOWR(IO_MAGICNUMBER, 3, cmd_io_t)
#define IO_WAIT _IOWR(IO_MAGICNUMBER, 4, cmd_io_t)
#define IO_MEM _IOWR(IO_MAGICNUMBER, 5, cmd_io_t)
#define IO_MOD _IOWR(IO_MAGICNUMBER, 6, cmd_io_t)

#endif