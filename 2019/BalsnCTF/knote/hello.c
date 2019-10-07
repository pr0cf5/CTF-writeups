#include <linux/module.h>     /* Needed by all modules */ 
#include <linux/kernel.h>     /* Needed for KERN_INFO */ 
#include <linux/init.h>       /* Needed for the macros */
#include <linux/sched.h> 
#include <stddef.h>
  
///< The license type -- this affects runtime behavior 
MODULE_LICENSE("GPL"); 
  
///< The author -- visible when you use modinfo 
MODULE_AUTHOR("Akshat Sinha"); 
  
///< The description -- see modinfo 
MODULE_DESCRIPTION("A simple Hello world LKM!"); 
  
///< The version of the module 
MODULE_VERSION("0.1"); 
  
static int __init hello_start(void) 
{ 
    printk(KERN_INFO "Loading hello module...\n"); 
    printk(KERN_INFO "Hello world\n"); 
    return 0; 
} 
  
static void __exit hello_end(void) 
{ 
    printk(KERN_INFO "task struct: %p\n", offsetof(struct mm_struct, pgd));
    printk(KERN_INFO "Goodbye Mr.\n"); 
    printk(KERN_INFO "haha\n");
} 
  
module_init(hello_start); 
module_exit(hello_end); 
