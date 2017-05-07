#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/ioctl.h>

//kmalloc
#include <linux/slab.h>

#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/capability.h>

#include "ksh.h"

MODULE_DESCRIPTION("Module ksh pour noyau linux");
MODULE_AUTHOR("F et Y, M1SAR");
MODULE_LICENSE("GPL");

struct ksh_ctx {
	struct list_head cmd_list;
	struct mutex lock_cmd_list;
	unsigned int cmd_count;
};
static struct ksh_ctx *ksh_ctx;

struct ksh_cmd {
	cmd_io_t args;
	struct list_head l_next;
	struct work_struct work;
    struct file *file;
};

int major;

static void  worker_list(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_list: is_async=%hu\n", cmd->args.is_async);
}

static void worker_fg(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_fg: is_async=%hu id=%lu\n", cmd->args.is_async, 
		cmd->args.fg_args.cmd_id);
}

static void worker_kill(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_kill: is_async=%hu signal=%d pid=%d\n", 
		cmd->args.is_async, 
		cmd->args.kill_args.signal, 
		cmd->args.kill_args.pid);
}

static void worker_wait(struct work_struct *wk) {
	int i;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_wait: is_async=%hu ", cmd->args.is_async);
	for(i = 0; i < cmd->args.wait_args.pid_count; i++) {
		pr_info("pid=%d ", cmd->args.wait_args.pids[i]);
	}
	pr_info("\n");
}

static void worker_meminfo(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_meminfo: is_async=%hu\n", cmd->args.is_async);
}

static void worker_modinfo(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_modinfo: is_async=%hu modname=%s\n", cmd->args.is_async,
		cmd->args.modinfo_args.str_ptr);
}


static long ksh_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

	int err = 0;
	int arg_length = 0;
	cmd_io_t *user_cmd;
	struct ksh_cmd *new_cmd;

	if (_IOC_TYPE(cmd) != KSH_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > KSH_IOC_MAXNR) return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_READ)
	    err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
	    err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err) return -EFAULT;

	// déclarée dans le .h permet de hack aux niveaux des structures pour récuperer les arguments dans les fonctions passées aux workqueues
	user_cmd = (cmd_io_t *) arg;
	new_cmd = (struct ksh_cmd *) kmalloc(sizeof(struct ksh_cmd), GFP_KERNEL);
	if(new_cmd == NULL) {
		pr_info("kmalloc failed, aborting ioctl operation\n");
		return -1;
	}

	copy_from_user(&(new_cmd->args), user_cmd, sizeof(cmd_io_t));
	new_cmd->file = file;
	
	switch(cmd)
	{
		case IO_LIST:
			INIT_WORK(&(new_cmd->work), worker_list);
			schedule_work(&new_cmd->work);
			break;
		case IO_FG:
			INIT_WORK(&(new_cmd->work), worker_fg);
			schedule_work(&new_cmd->work);
			break;
		case IO_KILL:
			INIT_WORK(&(new_cmd->work), worker_kill);
			schedule_work(&new_cmd->work);
			break;
		case IO_WAIT:
			arg_length = user_cmd->wait_args.pid_count;
			new_cmd->args.wait_args.pid_count = arg_length;
			new_cmd->args.wait_args.pids = (int *) 
				kmalloc(sizeof(int) * arg_length, GFP_KERNEL);
			if(new_cmd->args.wait_args.pids == NULL) {
				pr_info("kmalloc failed, aborting ioctl operation\n");
				kfree(new_cmd);
				return -1;
			}
			copy_from_user(new_cmd->args.wait_args.pids, 
				user_cmd->wait_args.pids, sizeof(int)*arg_length);

			INIT_WORK(&(new_cmd->work), worker_wait);
			schedule_work(&new_cmd->work);
			break;
		case IO_MEM:
			INIT_WORK(&(new_cmd->work), worker_meminfo);
			schedule_work(&new_cmd->work);
			break;
		case IO_MOD:
			arg_length = user_cmd->modinfo_args.str_len;
			new_cmd->args.modinfo_args.str_len = arg_length;
			new_cmd->args.modinfo_args.str_ptr = 
				(char *) kmalloc(sizeof(char) * arg_length, GFP_KERNEL);
			if(new_cmd->args.modinfo_args.str_ptr == NULL) {
				pr_info("kmalloc failed, aborting ioctl operation\n");
				kfree(new_cmd);
				return -1;
			}
			copy_from_user(new_cmd->args.modinfo_args.str_ptr, 
				user_cmd->modinfo_args.str_ptr, sizeof(char) * arg_length);

			INIT_WORK(&(new_cmd->work), worker_modinfo);
			schedule_work(&new_cmd->work);
			break;
		default:
			return -ENOTTY;
	}

	return err;

}

static int __init ksh_init(void)
{
	const struct file_operations ksh_fops = {.unlocked_ioctl = &ksh_ioctl, };
	pr_info("Init KSH IOCTL\n");

	major = register_chrdev(0, "ksh", &ksh_fops);

	pr_info("ksh_ioctl major: %d\n", major);

	ksh_ctx = (struct ksh_ctx *) kmalloc(sizeof(struct ksh_ctx), GFP_KERNEL);
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

	//TODO: kfree et destroy la mem
}
module_exit(ksh_exit);