#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include "helloioctl.h"

MODULE_DESCRIPTION("Module helloioctl pour noyau linux");
MODULE_AUTHOR("F et Y, M1SAR");
MODULE_LICENSE("GPL");

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


long ksh_ioctl(struct file * file, unsigned int cmd, unsigned long arg) {

	struct work_data data = kmalloc(sizeof(work_data));// déclarée dans le .h permet de hack aux niveaux des structures pour récuperer les arguments dans les fonctions passées aux workqueues
	data.file = file;
	data.arg = (char*) arg; //possibilité de check si c'est synchrone, mettre le '&' comme le 1er argument, et check ici
	
	switch(cmd)
	{
		case LIST:
			INIT_WORK(data->work,list);
			schedule_work(data->work);
			break;
		case FG:
			INIT_WORK(data->work,foreground);
			schedule_work(data->work);
			break;
		case KILL:
			INIT_WORK(data->work,mykill);
			schedule_work(data->work);
			break;
		case WAIT:
			INIT_WORK(data->work,mywait);
			schedule_work(data->work);
			break;
		case MEM:
			INIT_WORK(data->work,meminfo);
			schedule_work(data->work);
			break;
		case MOD:
			INIT_WORK(data->work,modinfo);
			schedule_work(data->work);
			break;
			
	}
			

	return (long)-ENOTTY;

}

static int __init ksh_init(void)
{
	const struct file_operations hellofops = {.unlocked_ioctl = &ksh_ioctl, };
	pr_info("Hello, IOCTL\n");

	//hellofops.unlocked_ioctl = &hello_ioctl;
	major = register_chrdev(0, "hello", &hellofops);

	pr_info("helloioctl major: %d\n", major);

	return 0;
}
module_init(ksh_init);

static void __exit ksh_exit(void)
{
	pr_info("Goodbye, IOCTL\n");

	unregister_chrdev(major, "hello");
}
module_exit(ksh_exit);