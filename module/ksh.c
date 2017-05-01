#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "ksh.h"

MODULE_DESCRIPTION("Module helloioctl pour noyau linux");
MODULE_AUTHOR("F et Y, M1SAR");
MODULE_LICENSE("GPL");

long hello_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

	char *user = (char *) arg;
	char *text = "Hello ioctl!";

	if(cmd == HELLO) {
		copy_to_user(user, text, strlen(text)+1);
		return 0;
	}

	return (long)-ENOTTY;

}

const struct file_operations hellofops = {
	.unlocked_ioctl = &hello_ioctl, 
};
static int major;

static int __init hello_init(void)
{
	pr_info("Hello, IOCTL\n");

	major = register_chrdev(0, "hello", &hellofops);

	pr_info("helloioctl major: %d\n", major);

	return 0;
}
module_init(hello_init);

static void __exit hello_exit(void)
{
	pr_info("Goodbye, IOCTL\n");

	unregister_chrdev(major, "hello");
}
module_exit(hello_exit);