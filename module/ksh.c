#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/mutex.h>

#include "ksh.h"

MODULE_DESCRIPTION("Module ksh pour noyau linux");
MODULE_AUTHOR("F et Y, M1SAR");
MODULE_LICENSE("GPL");

typedef struct {
	struct list_head cmd_list;
	struct mutex lock_cmd_list;
	unsigned int cmd_count;
} ksh_ctx_t;
static ksh_ctx_t *ksh_ctx;

typedef struct {
	cmd_io_t cmd_args;
	struct list_head l_next;
	struct work_struct work;
    struct file  *file;
} ksh_cmd_t;

int major;

void  list(struct work_struct*){
	//exemple pour récuperer arguments:
	struct work_data * data = (struct work_data *)work;

}

void foreground(struct work_struct*){

}

void mykill(struct work_struct*){

}

void mywait(struct work_struct*){

}

void meminfo(struct work_struct*){

}

void modinfo(struct work_struct*){

}


static long ksh_ioctl(struct file * file, unsigned int cmd, unsigned long arg) {

	ksh_cmd_t cmd = kmalloc(sizeof(ksh_cmd_t));// déclarée dans le .h permet de hack aux niveaux des structures pour récuperer les arguments dans les fonctions passées aux workqueues
	cmd.file = file;
	cmd.arg = (char*) arg; //possibilité de check si c'est synchrone, mettre le '&' comme le 1er argument, et check ici
	
	switch(cmd)
	{
		case IO_LIST:
			INIT_WORK(data->work,list);
			schedule_work(data->work);
			break;
		case IO_FG:
			INIT_WORK(data->work,foreground);
			schedule_work(data->work);
			break;
		case IO_KILL:
			INIT_WORK(data->work,mykill);
			schedule_work(data->work);
			break;
		case IO_WAIT:
			INIT_WORK(data->work,mywait);
			schedule_work(data->work);
			break;
		case IO_MEM:
			INIT_WORK(data->work,meminfo);
			schedule_work(data->work);
			break;
		case IO_MOD:
			INIT_WORK(data->work,modinfo);
			schedule_work(data->work);
			break;
			
	}
			

	return (long)-ENOTTY;

}

static int __init ksh_init(void)
{
	const struct file_operations ksh_fops = {.unlocked_ioctl = &ksh_ioctl, };
	pr_info("Init KSH IOCTL\n");

	major = register_chrdev(0, "ksh", &ksh_fops);

	pr_info("ksh_ioctl major: %d\n", major);

	ksh_ctx = kmalloc(sizeof(ksh_ctx_t), GFP_KERNEL);
	INIT_LIST_HEAD(&(ksh_ctx->cmd_list));
	ksh_ctx->cmd_count = 0;
	mutex_init(&ksh_ctx->lock_cmd_list);

	return 0;
}
module_init(ksh_init);

static void __exit ksh_exit(void)
{
	pr_info("Exit KSH IOCTL\n");

	unregister_chrdev(major, "ksh");
}
module_exit(ksh_exit);