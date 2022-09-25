#include "challenge_module.h"

MODULE_LICENSE("GPL");

struct proc_dir_entry *proc_entry;

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    return -EINVAL;
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    /* read data from user */
    char user_data[1024];
    if (len > 1024) {
        if(copy_from_user(user_data, buf, 1024)) {
            return -EINVAL;
        }
    }
    else {
        if (copy_from_user(user_data, buf, len)) {
            return -EINVAL;
        }
    }

    if (!exec_user_data(user_data)) {
        return -EINVAL;
    }

    return strlen(user_data);
}

static int challenge_open(struct inode *inode, struct file *fp)
{
    return 0;
}

static int challenge_release(struct inode *inode, struct file *fp)
{
    return 0;
}

static struct file_operations fops = {
    .read    = challenge_read,
    .write   = challenge_write,
    .open    = challenge_open,
    .release = challenge_release
};

int init_module(void)
{
    proc_entry = proc_create("challenge", 0666, NULL, &fops);
    return 0;
}

void cleanup_module(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
    }
}
