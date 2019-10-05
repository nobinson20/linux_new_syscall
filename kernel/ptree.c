#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kfifo.h> /* for kfifo queue */

/***********     FUNCTIONS     ***********/

/* Use the following function to get the task_struct given pid
 * (Don't worry about namespaces and virtual pids):
*/
static struct task_struct *get_root(int root_pid)
{
    if (root_pid == 0)
        return &init_task;

    return find_task_by_vpid(root_pid);
}

// Changed a bit 'is_process_or_thread()' below.
int is_process(struct task_struct *task)
{
    //TODO: find a macro tht does this
    // maybe get_pid or something check link below task_pid_nr
    // task_gid_nr
    // https://elixir.bootlin.com/linux/v4.14.112/source/include/linux/sched.h#L1196
    if (task -> tgid == task -> pid)
        return 1;
    return 0;
}





/*
* function: 'has_children'
* This function checks whether or not a task has children.
* @param: struct task_struct *task
* @return value: int (0 or 1)
*/
int has_children (struct task_struct *task){
    if ( (task==NULL) || list_empty(&task->children) )
        return 0; // no children or task is unvalid.
    return 1;
}

// Byeongho's version
// I just changed it to return pointer.
struct prinfo *task_to_prinfo(struct task_struct *task)
{
    //convert task to prinfo struct
    struct prinfo *prtask = NULL;

    prtask->parent_pid = task->real_parent->pid;
    prtask->pid = task->pid;
    prtask->state = task->state;
    prtask->uid = task->real_cred->uid.val;
    strcpy(prtask->comm, task->comm);

    return prtask;
}

// Byeongho's version
int *bfs_task (struct prinfo *kernel_buf, int *kernel_nr, int root_pid){
    int tc = 0; // task counter (number of total tasks)
    int num = *(kernel_nr);
    int lc = 0; // level counter
    int i = 0, j = 0;
    int *ret;
    struct task_struct *root_task = get_root(root_pid);
    struct task_struct *mytask;
    struct task_struct *task;

    if(!is_process(root_task)){
        ret[0] = -1;
        return ret; // root_pid is not valid process
    }else
        tc ++;


    while (has_children(root_task)){
        list_for_each_entry (mytask, &mytask->children, sibling){
            if (is_process(mytask))
                tc++;
            *(root_task + tc) = *mytask;
        }
        if (tc >= num) // We count up to *(kernel_nr) at most. Thus, tc <= num.
            break;
    }

    // Copy root_task info to kernel_buf in prinfo version.
    while (i <= tc){
        *(kernel_buf + i) = *(task_to_prinfo (root_task + i));
        i++;
    }

    /* Now kernel_buf is all set except 'level' entry.
     * This section adds level to kernel_buf.
     */
    task = root_task;
    while (j <= tc){
        while (task != root_task){
            task = task->parent;
            lc++;
        }
        (kernel_buf + i)->level = lc;
        j++;
        task = task + j;
    }
    ret[0] = 0;
    return ret;
}






/***********     END OF FUNCTIONS     ***********/


/*
 * NOTE: the signature needs to have type and pointer together (not pointer and var name)
 * nr is the size of the buffer by the user
 */

SYSCALL_DEFINE3(ptree, struct prinfo *, buf, int *, nr, int, root_pid)
{
/* conforming to ISO C90, declarations come before code */
int num_from_user;


// Byeongho's version
int *ret_value;
//int b;

printk(" ******    Entered syscall ptree     ***** \n");
/****    VERIFICATION    ****/
/* Copies *nr value to integer,
 * this is the requested nodes from user
 */
get_user(num_from_user, nr);

/* Verify parameters are valid */
if ( (buf==NULL) || (nr==NULL) || (num_from_user < 1) )
return -EINVAL;

/*Root pid should be >= 0, if not set it to 0 */
if (root_pid < 0)
root_pid = 0;


// TODO: should we use kvmalloc? its virtual and not reliant on contiguous block of mem...
// TODO: ref: https://people.netfilter.org/rusty/unreliable-guides/kernel-hacking/routines-kmalloc.html

/* Allocate buffer in kernel */
printk("Allocating kernel buffer, to same size as user\n");
struct prinfo *kernel_buf = kmalloc(sizeof(struct prinfo) * (num_from_user), GFP_KERNEL);
if (kernel_buf == NULL){
printk("ERROR: Failed to allocate kernel buffer!\n");
return -11; //TODO: write down return values and their meanings, 11 is arbitrary
}else
printk("SUCCESS: allocated kernel buffer\n");



/***
   Enter the function that does all of the work
   create lock here and isolate the critical space to just one function
   enter_BFS() will do all of the work to keep the SYSCALL_DEFINE short
   and to ensure that the lock is definetly being used correctly.
***/
read_lock(&tasklist_lock);
printk("enter_BFS\n");


// Byeongho's version.
ret_value = bfs_task (kernel_buf, &num_from_user, root_pid);
read_unlock(&tasklist_lock);
printk("Done with enter_BFS function\n");

//enq_ret = kfifo_in(&queue, &task1, sizeof(task1));
//printk("kfifo enq returned: %d", enq_ret);

/* once the buffer is set, copy to user */
copy_to_user(buf, kernel_buf, sizeof(struct prinfo) * (*nr));

kfree(kernel_buf);
return 0;
}



