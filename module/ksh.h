#ifndef KSH_H
#define KSH_H

/* Params IN */

typedef struct  {
	unsigned int list_size;
} cmd_list_args;

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
	unsigned int str_len;
} cmd_modinfo_args;

/* Params OUT */

typedef struct {
	unsigned long cmd_id;
	int cmd_type;
	unsigned short is_async;
} cmd_list_elem;

typedef struct {
	unsigned int elem_count;
	cmd_list_elem *list;
} cmd_list_resp;

typedef struct {
	int ret;
} cmd_kill_resp;

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

/*typedef union {
	cmd_list_resp list_resp;
	cmd_wait_resp wait_resp;
	cmd_meminfo_resp meminfo_resp;
	cmd_modinfo_resp modinfo_resp;
} cmd_fg_resp;*/

/* cmd_io_t: struct for communication between user and kernel space */

typedef struct {
	/* IN args */
	int ioctl_type;
	union {
		cmd_list_args list_args;
		cmd_fg_args fg_args;
		cmd_kill_args kill_args;
		cmd_wait_args wait_args;
		cmd_modinfo_args modinfo_args;
	};
	unsigned short is_async;
	/* OUT Args */
	union {
		cmd_list_resp list_resp;
		cmd_kill_resp kill_resp;
		cmd_wait_resp wait_resp;
		cmd_meminfo_resp meminfo_resp;
		cmd_modinfo_resp modinfo_resp;
		unsigned long cmd_id;
	};
} cmd_io_t;

#define KSH_IOC_MAGIC 'N'

#define IO_LIST _IOWR(KSH_IOC_MAGIC, 1, cmd_io_t)
#define IO_FG _IOWR(KSH_IOC_MAGIC, 2, cmd_io_t)
#define IO_KILL _IOWR(KSH_IOC_MAGIC, 3, cmd_io_t)
#define IO_WAIT _IOWR(KSH_IOC_MAGIC, 4, cmd_io_t)
#define IO_MEM _IOWR(KSH_IOC_MAGIC, 5, cmd_io_t)
#define IO_MOD _IOWR(KSH_IOC_MAGIC, 6, cmd_io_t)
#define IO_LIST_SIZE _IOR(KSH_IOC_MAGIC, 7, unsigned int)

#define KSH_IOC_MAXNR 7

#endif