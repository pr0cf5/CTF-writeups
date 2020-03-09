#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/slab_def.h>
#include <linux/tty.h>
#include <linux/pipe_fs_i.h>
#include <asm/syscalls.h>

static int __init lkm_example_init(void) {
	printk(KERN_INFO "offset: %lx\n", offsetof(struct task_struct, tasks));
	printk(KERN_INFO "offset: %lx\n", offsetof(struct task_struct, cred));
	printk(KERN_INFO "offset: %lx\n", offsetof(struct task_struct, pid));
	printk(KERN_INFO "offset: %lx\n", offsetof(struct cred, uid));
	printk(KERN_INFO "offset: %lx\n", offsetof(struct cred, gid));
	return 0;
}
static void __exit lkm_example_exit(void) {
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
