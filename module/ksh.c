#include <linux/init.h>

/* struct module*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

/*file_operations*/
#include <linux/fs.h>

/*copy_from/to_user*/
#include <linux/uaccess.h>

/*ioctl macros*/
#include <linux/ioctl.h>

/*kmalloc*/
#include <linux/slab.h>

#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/mutex.h>

/*kill_pid and task_struct*/
#include <linux/sched.h>
/* NSIG*/
#include <asm/signal.h>

/*wait_queue*/
#include <linux/wait.h>

/*find_vpid & get_pid_task*/
#include <linux/pid.h>

/*meminfo*/
#include <linux/mm.h>
#include <linux/swap.h>
#define P2K(x) ((x) << (PAGE_SHIFT - 10))

#include "ksh.h"

MODULE_DESCRIPTION("Module ksh pour noyau linux");
MODULE_AUTHOR("F et Y, M1SAR");
MODULE_VERSION("0.4.2");
MODULE_LICENSE("GPL");

struct wait_ctx_s {
	struct pid **pid_list;
	struct task_struct **task_list;
	unsigned short wait_already_executed;
};

struct ksh_ctx_s {
	struct list_head cmd_list;
	struct mutex lock_ctx;
	unsigned long cmd_count;
	unsigned int list_size;
	int major_num;
};
static struct ksh_ctx_s *ksh_ctx;

struct ksh_cmd {
	unsigned int cmd_type;
	cmd_io_t args;
	struct list_head l_next;
	union {
		struct work_struct work;
		struct delayed_work dwork;
	};
	unsigned long cmd_id;
	wait_queue_head_t wait_done;
	unsigned short is_finished;
	cmd_io_t *user_cmd;
	struct wait_ctx_s wait_ctx;
};

static void remove_from_cmd_list(struct ksh_cmd *cmd)
{
	mutex_lock(&ksh_ctx->lock_ctx);
	list_del(&cmd->l_next);
	ksh_ctx->list_size--;
	mutex_unlock(&ksh_ctx->lock_ctx);
}

static struct ksh_cmd *find_cmd_by_id(unsigned long id)
{
	struct ksh_cmd *iter;
	struct ksh_cmd *found = NULL;

	mutex_lock(&ksh_ctx->lock_ctx);

	list_for_each_entry(iter, &ksh_ctx->cmd_list, l_next) {
		if (iter->cmd_id == id) {
			found = iter;
			break;
		}
	}

	mutex_unlock(&ksh_ctx->lock_ctx);

	return found;
}

/* Waits for cmd 'cmd' to finish and give
its results to give_to user cmd */
static void wait_and_give_resp(struct ksh_cmd *cmd,
	struct ksh_cmd *give_to) {
	wait_event(cmd->wait_done, cmd->is_finished);

	remove_from_cmd_list(cmd);

	switch (cmd->cmd_type) {
	case IO_LIST:
			copy_to_user(give_to->user_cmd->list_resp.list,
				cmd->args.list_resp.list,
				cmd->args.list_resp.elem_count *
				sizeof(cmd_list_elem));
			copy_to_user(&give_to->user_cmd->list_resp.elem_count,
				&cmd->args.list_resp.elem_count,
				sizeof(unsigned int));
			kfree(cmd->args.list_resp.list);
			break;
		case IO_FG:
			pr_debug("Weird, shouldnt give response for async FG\n");
			break;
	case IO_KILL:
			copy_to_user(&give_to->user_cmd->kill_resp.ret,
				&cmd->args.kill_resp.ret, sizeof(int));
			break;
	case IO_WAIT:
			copy_to_user(&give_to->user_cmd->wait_resp,
				&cmd->args.wait_resp, sizeof(cmd_wait_resp));
			kfree(cmd->args.wait_args.pids);
			break;
	case IO_MEM:
			copy_to_user(&give_to->user_cmd->meminfo_resp,
				&cmd->args.meminfo_resp,
				sizeof(cmd_meminfo_resp));
			break;
	case IO_MOD:
		copy_to_user(give_to->user_cmd->modinfo_resp.res_buffer,
			cmd->args.modinfo_resp.res_buffer, 
			cmd->args.modinfo_resp.res_buf_size * sizeof(char));
		copy_to_user(&give_to->user_cmd->modinfo_resp.ret,
			&cmd->args.modinfo_resp.ret, sizeof(int));

		kfree(cmd->args.modinfo_args.str_ptr);
		kfree(cmd->args.modinfo_resp.res_buffer);
			break;
	default:
			return;
	}

	kfree(cmd);
}

static void  worker_list(struct work_struct *wk)
{
	unsigned int list_size;
	unsigned int i;
	struct ksh_cmd *iter;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_debug("worker_list: is_async=%hu\n", cmd->args.is_async);

	mutex_lock(&ksh_ctx->lock_ctx);

	if (cmd->args.list_args.list_size > ksh_ctx->list_size)
		list_size = ksh_ctx->list_size;
	else
		list_size = cmd->args.list_args.list_size;

	i = 0;
	list_for_each_entry(iter, &ksh_ctx->cmd_list, l_next) {
		if (i > list_size)
			break;
		cmd->args.list_resp.list[i].cmd_type = iter->cmd_type;
		cmd->args.list_resp.list[i].is_async = iter->args.is_async;
		cmd->args.list_resp.list[i].cmd_id = iter->cmd_id;
		pr_debug("%d list %d %hu %lu\n", i, iter->cmd_type,
			iter->args.is_async, iter->cmd_id);
		i++;
	}

	mutex_unlock(&ksh_ctx->lock_ctx);
	cmd->args.list_resp.elem_count = list_size;

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static int handle_fg(struct ksh_cmd *cmd)
{
	struct ksh_cmd *found;

	pr_debug("handle_fg: is_async=%hu id=%lu\n", cmd->args.is_async,
		cmd->args.fg_args.cmd_id);

	found = find_cmd_by_id(cmd->args.fg_args.cmd_id);

	if (found == NULL) {
		pr_debug("Unable to find cmd_id: %lu\n",
			cmd->args.fg_args.cmd_id);
		return -1;
	} else {
		/* Give the response to the fg command */
		wait_and_give_resp(found, cmd);
		return 0;
	}
}

static void worker_kill(struct work_struct *wk)
{
	struct pid *pid_s;
	int resp;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_debug("worker_kill: is_async=%hu signal=%d pid=%d\n",
		cmd->args.is_async,
		cmd->args.kill_args.signal,
		cmd->args.kill_args.pid);

	if (cmd->args.kill_args.signal > _NSIG
		|| cmd->args.kill_args.signal < 1) {
		resp = -1;
	} else {
		pid_s = find_get_pid(cmd->args.kill_args.pid);
		if (pid_s)
			resp = kill_pid(pid_s, cmd->args.kill_args.signal, 1);
		else
			resp = -2;
	}

	cmd->args.kill_resp.ret = resp;

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_wait(struct work_struct *wk)
{
	int i;
	int null_count;
	unsigned short already_executed;
	struct pid *pid_s;
	struct task_struct *task_s;
	struct pid **save_pid;
	struct task_struct **save_task;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);
	int pid_count = cmd->args.wait_args.pid_count;
	int *pids = cmd->args.wait_args.pids;

	pr_debug("worker_wait: is_async=%hu ", cmd->args.is_async);
	for (i = 0; i < pid_count; i++)
		pr_debug("pid=%d ", pids[i]);
	pr_debug("\n");

	null_count = 0;
	already_executed = cmd->wait_ctx.wait_already_executed;
	if(!already_executed) {
		save_pid = (struct pid **) 
		kmalloc(pid_count * sizeof(struct pid *), GFP_KERNEL);
		save_task = (struct task_struct **) 
		kmalloc(pid_count * sizeof(struct task_struct *), GFP_KERNEL);
		cmd->wait_ctx.pid_list = save_pid;
		cmd->wait_ctx.task_list = save_task;
	} else {
		save_pid = cmd->wait_ctx.pid_list;
		save_task = cmd->wait_ctx.task_list;
	}

	for(i = 0; i < pid_count; i++) {
		if((pid_s = find_vpid(pids[i])) == NULL) {
			if(++null_count == pid_count && !already_executed) {
				pr_debug("All pids doesnt exist\n");
				cmd->args.wait_resp.ret = -1;
				cmd->is_finished = 1;
				break;
			}
			else if(already_executed && pid_s == NULL) {
				pr_debug("pid=%d finished\n", pids[i]);
				if(save_task[i] != NULL) {
					cmd->args.wait_resp.pid = save_task[i]->pid;
					cmd->args.wait_resp.exit_code = save_task[i]->exit_code;
				}
				cmd->args.wait_resp.ret = 0;
				cmd->is_finished = 1;
				break;
			} 
		} else {
			save_pid[i] = pid_s;
			if((task_s = get_pid_task(pid_s, PIDTYPE_PID)) 
				!= NULL) {
				save_task[i] = task_s;
			}
		}
	}

	if(!cmd->is_finished) {
		cmd->wait_ctx.wait_already_executed = 1;
		pr_debug("Retrying wait in 5 seconds\n");
		schedule_delayed_work(&cmd->dwork, 5*HZ);
		return;
	}

	kfree(cmd->wait_ctx.pid_list);
	kfree(cmd->wait_ctx.task_list);

	wake_up(&cmd->wait_done);
}

static void worker_meminfo(struct work_struct *wk)
{
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);
	static struct sysinfo val;
	cmd_meminfo_resp *mem_data;

	pr_debug("worker_meminfo: is_async=%hu\n", cmd->args.is_async);

	mem_data = &cmd->args.meminfo_resp;

	si_meminfo(&val);
	si_swapinfo(&val);
	/* si_swapinfo is not exported, cannot
	use it without changing kernel sources ! */

	mem_data->sharedram = val.sharedram;
	mem_data->totalram  = (unsigned long) P2K(val.totalram);
	mem_data->freeram   = (unsigned long) P2K(val.freeram);
	mem_data->totalhigh = (unsigned long) P2K(val.totalhigh);
	mem_data->freehigh  = (unsigned long) P2K(val.freehigh);
	mem_data->bufferram = (unsigned long) P2K(val.bufferram);
	mem_data->cached    = (unsigned long)
	P2K(global_page_state(NR_FILE_PAGES) - val.bufferram);

	mem_data->totalswap = (unsigned long) P2K(val.totalswap);
	mem_data->freeswap  = (unsigned long) P2K(val.freeswap);


	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}

static void worker_modinfo(struct work_struct *wk) {
	struct module *module_s;
	int written;
	int buf_size;
	int bytes_left;
	char *buf;
	struct ksh_cmd *cmd = container_of(wk, struct ksh_cmd, work);

	pr_debug("worker_modinfo: is_async=%hu modname=%s\n",
		cmd->args.is_async, cmd->args.modinfo_args.str_ptr);

	buf = cmd->args.modinfo_resp.res_buffer;
	buf_size = cmd->args.modinfo_resp.res_buf_size;
	bytes_left = buf_size;
	written = 0;

	if (mutex_lock_interruptible(&module_mutex) != 0) {
		pr_debug("Retrying lock module_mutex\n");
		schedule_delayed_work(&cmd->dwork, HZ);
		return;
	}

	module_s = find_module(cmd->args.modinfo_args.str_ptr);
	if (module_s) {
		do {
			pr_debug("mod nom: %s\n", module_s->name);
			bytes_left = buf_size - written;
			written += scnprintf(&buf[written], bytes_left, 
				"Name: %s\n", module_s->name);
			if(written + 1 >= buf_size)
				break;

			pr_debug("mod version: %s\n", module_s->version);
			bytes_left = buf_size - written;
			written += scnprintf(&buf[written], bytes_left, 
				"Version: %s\n", module_s->version);
			if(written + 1 >= buf_size)
				break;

			pr_debug("mod load addr: 0x%p\n", module_s->module_core);
			bytes_left = buf_size - written;
			written += scnprintf(&buf[written], bytes_left, 
				"Load addr: %p\n", module_s->module_core);
			if(written + 1 >= buf_size)
				break;

			if(module_s->args) {
				pr_debug("mod args: %s\n", module_s->args);
				bytes_left = buf_size - written;
				written += scnprintf(&buf[written], bytes_left, 
					"Arguments: %s\n", module_s->args);
				if(written + 1 >= buf_size)
					break;
			}

		} while (0);

		buf[buf_size-1] = '\0';
		cmd->args.modinfo_resp.ret = 0;
	} else {
		cmd->args.modinfo_resp.ret = -1;
	}

	mutex_unlock(&module_mutex);

	cmd->is_finished = 1;
	wake_up(&cmd->wait_done);
}


static long ksh_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg) {

	int err = 0;
	int arg_length = 0;
	cmd_io_t *user_cmd;
	struct ksh_cmd *new_cmd;
	struct ksh_cmd *found_cmd;
	unsigned int future_list_size;
	unsigned int *user_list_size;
	int tmp;
	unsigned long cmd_id;

	if (_IOC_TYPE(cmd) != KSH_IOC_MAGIC)
		return -ENOTTY;
	if (_IOC_NR(cmd) > KSH_IOC_MAXNR)
		return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_READ)
	    err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
	    err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err)
		return -EFAULT;

	/* In case of IO_LIST_SIZE cmd, give the size the list will have
		for the next IO_LIST cmd */
	if (cmd == IO_LIST_SIZE) {
		user_list_size = (unsigned int *) arg;
		mutex_lock(&ksh_ctx->lock_ctx);
		future_list_size = ksh_ctx->list_size + 1;
		mutex_unlock(&ksh_ctx->lock_ctx);
		err = copy_to_user(user_list_size, &future_list_size,
			sizeof(unsigned int));
		return err;
	}

	user_cmd = (cmd_io_t *) arg;

	/* fg and wait commands cannot run asynchronously */
	if (user_cmd->is_async && (cmd == IO_FG || cmd == IO_WAIT))
		return -ENOTTY;

	if (cmd == IO_FG_TYPE) {
		err = copy_from_user(&cmd_id,
			&user_cmd->fg_args.cmd_id, sizeof(unsigned long));
		found_cmd = find_cmd_by_id(cmd_id);
		if (found_cmd == NULL) {
			pr_debug("Command with id: %lu not found\n", cmd_id);
			tmp = -1;
			err = copy_to_user(&user_cmd->fg_type_resp.fg_cmd_type,
				&tmp, sizeof(int));
		} else {
			err = copy_to_user(&user_cmd->fg_type_resp.fg_cmd_type,
				&found_cmd->cmd_type, sizeof(int));
		}
		return err;
	}

	new_cmd = (struct ksh_cmd *)
	kmalloc(sizeof(struct ksh_cmd), GFP_KERNEL);
	if (new_cmd == NULL) {
		pr_debug("kmalloc failed, aborting ioctl operation\n");
		return -1;
	}


	err = copy_from_user(&(new_cmd->args), user_cmd, sizeof(cmd_io_t));

	new_cmd->user_cmd = user_cmd;
	new_cmd->cmd_type = cmd;
	init_waitqueue_head(&new_cmd->wait_done);
	new_cmd->is_finished = 0;
	mutex_lock(&ksh_ctx->lock_ctx);
	new_cmd->cmd_id = ++ksh_ctx->cmd_count;
	list_add(&new_cmd->l_next, &ksh_ctx->cmd_list);
	ksh_ctx->list_size++;
	mutex_unlock(&ksh_ctx->lock_ctx);

	switch (cmd) {
	case IO_LIST:
			arg_length = user_cmd->list_args.list_size;
			new_cmd->args.list_resp.list = (cmd_list_elem *)
			kmalloc(arg_length * sizeof(cmd_list_elem), GFP_KERNEL);
			if (new_cmd->args.list_resp.list == NULL) {
				pr_debug("kmalloc failed, aborting ioctl operation\n");
				kfree(new_cmd);
				return -1;
			}
			INIT_WORK(&new_cmd->work, worker_list);
			schedule_work(&new_cmd->work);
			break;
	case IO_FG:
			remove_from_cmd_list(new_cmd);
			handle_fg(new_cmd);
			return err;
		case IO_KILL:
			INIT_WORK(&new_cmd->work, worker_kill);
			schedule_work(&new_cmd->work);
			break;
	case IO_WAIT:
			arg_length = user_cmd->wait_args.pid_count;
			new_cmd->args.wait_args.pid_count = arg_length;
			new_cmd->args.wait_args.pids = (int *)
				kmalloc(sizeof(int) * arg_length, GFP_KERNEL);
			if (new_cmd->args.wait_args.pids == NULL) {
				pr_debug("kmalloc failed, aborting ioctl operation\n");
				kfree(new_cmd);
				return -1;
			}
			err = copy_from_user(new_cmd->args.wait_args.pids,
			user_cmd->wait_args.pids, sizeof(int)*arg_length);

			new_cmd->wait_ctx.wait_already_executed = 0;

			INIT_DELAYED_WORK(&new_cmd->dwork, worker_wait);
			schedule_delayed_work(&new_cmd->dwork, 0);
			break;
		case IO_MEM:
			INIT_WORK(&new_cmd->work, worker_meminfo);
			schedule_work(&new_cmd->work);
			break;
	case IO_MOD:
			arg_length = user_cmd->modinfo_args.str_len;
			new_cmd->args.modinfo_args.str_len = arg_length;
			new_cmd->args.modinfo_args.str_ptr =
				kmalloc(sizeof(char) * arg_length, GFP_KERNEL);
			if (new_cmd->args.modinfo_args.str_ptr == NULL) {
				pr_debug("kmalloc failed, aborting ioctl operation\n");
				kfree(new_cmd);
				return -1;
			}
			err = copy_from_user(
				new_cmd->args.modinfo_args.str_ptr,
				user_cmd->modinfo_args.str_ptr,
				sizeof(char) * arg_length);

			arg_length = new_cmd->args.modinfo_resp.res_buf_size;
			new_cmd->args.modinfo_resp.res_buffer = (char *) 
				kmalloc(arg_length * sizeof(char), GFP_KERNEL);
			if(new_cmd->args.modinfo_resp.res_buffer == NULL) {
				pr_debug("kmalloc failed, aborting ioctl operation\n");
				kfree(new_cmd->args.modinfo_args.str_ptr);
				kfree(new_cmd);
				return -1;
			}

			INIT_DELAYED_WORK(&new_cmd->dwork, worker_modinfo);
			schedule_delayed_work(&new_cmd->dwork, 0);
			break;
	default:
			return -ENOTTY;
	}

	if (!new_cmd->args.is_async) {
		wait_and_give_resp(new_cmd, new_cmd);
	} else {
		err = copy_to_user(&user_cmd->cmd_id, &new_cmd->cmd_id,
			sizeof(unsigned long));
	}

	return err;
}

static const struct file_operations ksh_fops = {
	.unlocked_ioctl = ksh_ioctl
};

static int __init ksh_init(void)
{
	pr_info("Init ksh module\n");

	ksh_ctx = kmalloc(sizeof(struct ksh_ctx_s),
		GFP_KERNEL);
	if (ksh_ctx == NULL) {
		pr_debug("kmalloc failed, aborting ksh module init\n");
		return -1;
	}

	ksh_ctx->major_num = register_chrdev(0, "ksh", &ksh_fops);
	pr_info("ksh chrdev major: %d\n", ksh_ctx->major_num);
	INIT_LIST_HEAD(&(ksh_ctx->cmd_list));
	ksh_ctx->cmd_count = 0;
	ksh_ctx->list_size = 0;
	mutex_init(&ksh_ctx->lock_ctx);

	return 0;
}
module_init(ksh_init);

static void __exit ksh_exit(void)
{
	struct ksh_cmd *cmd;
	struct ksh_cmd *cmd_safe;
	pr_info("Exit ksh module\n");

	unregister_chrdev(ksh_ctx->major_num, "ksh");

	mutex_lock(&ksh_ctx->lock_ctx);

	list_for_each_entry_safe(cmd, cmd_safe, &ksh_ctx->cmd_list, l_next) {
		if(!cmd->is_finished) {
			if(cmd->cmd_type == IO_WAIT || cmd->cmd_type == IO_MOD) {
				cancel_delayed_work_sync(&cmd->dwork);
			} else {
				cancel_work_sync(&cmd->work);
			}
		}
		list_del(&cmd->l_next);
        kfree(cmd);
    }

	mutex_unlock(&ksh_ctx->lock_ctx);

	kfree(ksh_ctx);
}
module_exit(ksh_exit);