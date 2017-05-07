#include <linux/init.h>

// struct module
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

//file_operations
#include <linux/fs.h>

//copy_from/to_user
#include <asm/uaccess.h>

//ioctl macros
#include <linux/ioctl.h>

//kmalloc
#include <linux/slab.h>

#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/mutex.h>

//kill_pid
#include <linux/sched.h>
// NSIG
#include <asm/signal.h>

//wait_queue
#include <linux/wait.h>

#include "ksh.h"

MODULE_DESCRIPTION("Module ksh pour noyau linux");
MODULE_AUTHOR("F et Y, M1SAR");
MODULE_LICENSE("GPL");

struct ksh_ctx {
	struct list_head cmd_list;
	struct mutex lock_ctx;
	unsigned long cmd_count;
	unsigned int list_size;
	int major_num;
};
static struct ksh_ctx *ksh_ctx;

struct ksh_cmd {
	cmd_io_t args;
	struct list_head l_next;
	struct work_struct work;
    struct file *file;
    unsigned long cmd_id;
    wait_queue_head_t wait_done;
    unsigned short is_finished;
};

static void  worker_list(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_list: is_async=%hu\n", cmd->args.is_async);
	
	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_fg(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_fg: is_async=%hu id=%lu\n", cmd->args.is_async, 
		cmd->args.fg_args.cmd_id);


	//TODO: A enlever, fg pas async
	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_kill(struct work_struct *wk) {
	struct pid *pid_s;
	int resp;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_kill: is_async=%hu signal=%d pid=%d\n", 
		cmd->args.is_async, 
		cmd->args.kill_args.signal, 
		cmd->args.kill_args.pid);

	if(cmd->args.kill_args.signal > _NSIG 
		|| cmd->args.kill_args.signal < 1) {
		resp = -1;
	}
	else {
		pid_s = find_get_pid(cmd->args.kill_args.pid);
		if(pid_s) {
			resp = kill_pid(pid_s, cmd->args.kill_args.signal, 1);
		} else {
			resp = -2;
		}
	}

	copy_to_user(&cmd->args.kill_resp.ret, &resp, sizeof(int));

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_wait(struct work_struct *wk) {
	int i;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_wait: is_async=%hu ", cmd->args.is_async);
	for(i = 0; i < cmd->args.wait_args.pid_count; i++) {
		pr_info("pid=%d ", cmd->args.wait_args.pids[i]);
	}
	pr_info("\n");

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_meminfo(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_meminfo: is_async=%hu\n", cmd->args.is_async);

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_modinfo(struct work_struct *wk) {
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_info("worker_modinfo: is_async=%hu modname=%s\n", cmd->args.is_async,
		cmd->args.modinfo_args.str_ptr);

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}


static long ksh_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

	int err = 0;
	int arg_length = 0;
	cmd_io_t *user_cmd;
	struct ksh_cmd *new_cmd;
	int *user_list_size;

	if (_IOC_TYPE(cmd) != KSH_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > KSH_IOC_MAXNR) return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_READ)
	    err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
	    err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err) return -EFAULT;

	if(cmd == IO_LIST_SIZE) {
		user_list_size = (int *) arg;
		mutex_lock(&ksh_ctx->lock_ctx);
		err = copy_to_user(user_list_size, &ksh_ctx->list_size, sizeof(int));
		mutex_unlock(&ksh_ctx->lock_ctx);
		return err;
	}

	// déclarée dans le .h permet de hack aux niveaux des structures pour récuperer les arguments dans les fonctions passées aux workqueues
	user_cmd = (cmd_io_t *) arg;
	new_cmd = (struct ksh_cmd *) kmalloc(sizeof(struct ksh_cmd), GFP_KERNEL);
	if(new_cmd == NULL) {
		pr_info("kmalloc failed, aborting ioctl operation\n");
		return -1;
	}

	err = copy_from_user(&(new_cmd->args), user_cmd, sizeof(cmd_io_t));

	new_cmd->file = file;
	init_waitqueue_head(&new_cmd->wait_done);
	new_cmd->is_finished = 0;
	mutex_lock(&ksh_ctx->lock_ctx);
	new_cmd->cmd_id = ++ksh_ctx->cmd_count;
	list_add(&new_cmd->l_next, &ksh_ctx->cmd_list);
	ksh_ctx->list_size++;
	mutex_unlock(&ksh_ctx->lock_ctx);

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
			err = copy_from_user(new_cmd->args.wait_args.pids, 
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
			err = copy_from_user(new_cmd->args.modinfo_args.str_ptr, 
				user_cmd->modinfo_args.str_ptr, sizeof(char) * arg_length);

			INIT_WORK(&(new_cmd->work), worker_modinfo);
			schedule_work(&new_cmd->work);
			break;
		default:
			return -ENOTTY;
	}

	if(!new_cmd->args.is_async) {
		wait_event(new_cmd->wait_done, new_cmd->is_finished);
		mutex_lock(&ksh_ctx->lock_ctx);
		list_del(&new_cmd->l_next);
		ksh_ctx->list_size--;
		mutex_unlock(&ksh_ctx->lock_ctx);
		kfree(new_cmd);
	} else {
		err = copy_to_user(&user_cmd->cmd_id, &new_cmd->cmd_id, 
			sizeof(int));
	}

	return err;
}

static struct file_operations ksh_fops = {
	.unlocked_ioctl = ksh_ioctl
};

static int __init ksh_init(void)
{
	pr_info("Init KSH IOCTL\n");

	ksh_ctx = (struct ksh_ctx *) kmalloc(sizeof(struct ksh_ctx), GFP_KERNEL);
	if(ksh_ctx == NULL) {
		pr_info("kmalloc failed, aborting ksh module init\n");
		return -1;
	}

	ksh_ctx->major_num = register_chrdev(0, "ksh", &ksh_fops);
	pr_info("ksh_ioctl major: %d\n", ksh_ctx->major_num);
	INIT_LIST_HEAD(&(ksh_ctx->cmd_list));
	ksh_ctx->cmd_count = 0;
	ksh_ctx->list_size = 0;
	mutex_init(&ksh_ctx->lock_ctx);

	return 0;
}
module_init(ksh_init);

static void __exit ksh_exit(void)
{
	pr_info("Exit KSH IOCTL\n");

	unregister_chrdev(ksh_ctx->major_num, "ksh");

	//TODO: destroy les structs et kfree
	kfree(ksh_ctx);
}
module_exit(ksh_exit);