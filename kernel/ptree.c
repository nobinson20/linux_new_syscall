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

/*
 * Testing iterating children only
 * Same as iterate_children except using list_for_each_entry
 * Example from Kernel Dev book pg. 94
 */
int iterate_siblings(struct task_struct *task)
{

	int task_counter;
	//int level = 0;
	struct task_struct *mytask; // used to point to current entry
	printk("Entered iterate siblings\n");
	task_counter = 0;

	list_for_each_entry(mytask, &task->children, sibling)
	{
		/*TODO write a function here to check is entry is
		* process or a thread
		* TODO uncomment this block when ready to test P vs T
		
		pid_t tgid= task_tgid_vnr(mytask);
		pid_t pid = task_pid_vnr(mytask);
		printk("PID = %d; TGID = %d", pid, tgid);

		if (pid == tgid)
			printk("I'm a process and child of %s, and my info is %s[%d]\n", mytask->parent->comm, mytask->comm, mytask->pid);
		else
			printk("I'm a thread, a child of %s, and my info is %s[%d]\n", mytask->parent->comm, mytask->comm, mytask->pid);
		task_counter++;
		 */


		//int p_or_t;
		//p_or_t = is_process_or_thread(mytask);
		//printk("is a process or thread: %d\n", p_or_t);
		//printk("I'm a child of %s, and my info is %s[%d]\n", mytask->parent->comm, mytask->comm, mytask->pid);
	}
	return task_counter;
}

int is_process_or_thread(struct task_struct *task)
{	
	//TODO: find a macro tht does this 
	// maybe get_pid or something check link below task_pid_nr
	// task_gid_nr 
	// https://elixir.bootlin.com/linux/v4.14.112/source/include/linux/sched.h#L1196
	if (task->tgid == task->pid)
		return 1;
	return 0;
}


/* Function that takes */
struct prinfo task_to_prinfo(struct task_struct *task, int level_val)
{
	//convert task to prinfo struct
	struct prinfo prtask;

	prtask.parent_pid = task->real_parent->pid;
	prtask.pid = task->pid;
	prtask.state = task->state;
	prtask.uid = task->real_cred->uid.val;
	strcpy(prtask.comm, task->comm);
	prtask.level = level_val; //TODO not yet implemented

	return prtask;
}

int iterate_bfs_test(struct kfifo *bufq, struct kfifo *queue, int root_pid)
{
	/* TODO: initial tests OK (did not validate if proper order yet, and some other details
	 * but the part that works is that we traverse and get data out to user space
	 *
	 * TODO: Important to remember to return NR amount of processes
	 * TODO: we may be able to get level by counting children scanned
	 * then as we pop, decrement, and once we're at zero, we are up one level
	 *
	 * (not yet thinking of marking if visited as we may not run into this problem)
	 *
	 * create queue for bfs traversal "q"
	 * push first task (PID as ID?)
	 * loop: while q not empty
	 * 		pop element
	 * 			Add to our BUF
	 * 		get all children (walk siblings below)
	 * 			push said children to q
	 * REPEAT LOOP
	 */

	/* I did this on paper and the BUFF is in proper order */
	int enq_ret, ret; /* returned written or read bytes in queue, used to check if proper amount of bytes was r/w */
	struct task_struct *task = get_root(root_pid); /* get task struct */
	int level_count = 0;
	int level = 0;
	struct task_struct *mytask; // used to point to current entry
	struct prinfo my_prinfo;
	struct prinfo received_pri; /* to be used when popping*/
	
	if (task == NULL) {
		printk("Task returned null!\n");
		return -12;
	}

	/* lets get a prinfo object from our task */
	my_prinfo = task_to_prinfo(task, level);
	
	/* enqueue the root task as prinfo object */
	printk("*********** About to enqueue prinfo \n");
	enq_ret = kfifo_in(queue, &my_prinfo, sizeof(my_prinfo));
	printk("*********** kfifo enq returned: %d\n", enq_ret);
	if (enq_ret != sizeof(my_prinfo))
		return -EINVAL;

	//int ret;

	// while q not empty. function returns 0 if not empty
	while (kfifo_is_empty(queue) == 0)
	{
		/* while there's data available */
		while (kfifo_avail(queue)) {

			/* pop our task */
			ret = kfifo_out(queue, &received_pri, sizeof(received_pri));
			if (ret != sizeof(received_pri))
				return -EINVAL;

			/* add to our buffer */
			ret = kfifo_in(bufq, &received_pri, sizeof(received_pri));
			if (ret != sizeof(received_pri))
				return -EINVAL;

			/* get children */
			/* push all children down */

			/* first lets get a task object from our prinfo we popped */
			task = get_root(received_pri.pid); /* get task struct of our popped prinfo obj*/
			if (task == NULL) {
				printk("Error retrieving task by prinfo pid!\n");
				return 20;
			}

			//int task_counter;
			//struct task_struct *mytask; // used to point to current entry
			printk("About to iterate children\n");
			//task_counter = 0;
			if (level_count == 0)
				level = level + 1;
			else
				level_count = level_count - 1;
			list_for_each_entry(mytask, &task->children, sibling)
			{
				//TODO: is it safe ot reuse my_prinfo here? Should be... pc2550
				my_prinfo = task_to_prinfo(mytask, level);

				//TODO should we check if buffer has enough space?

				/* enqueue the child task as prinfo object */
				printk("*********** enqueueing children in foreachloop \n");
				if (is_process_or_thread(mytask) == 1){
					enq_ret = kfifo_in(queue, &my_prinfo, sizeof(my_prinfo));
					level_count = level_count + 1;
					printk("*********** kfifo enq returned: %d\n", enq_ret);
					if (enq_ret != sizeof(my_prinfo))
						return -EINVAL; //TODO check for these? what's the value =?
				}
			}
		}
	}
	return 0;
}


/***
* This is where all of the logic behind doing BFS will go, ideally this
* will only call other functions that will do one thing
***/
int enter_BFS(struct prinfo* kernel_buf, int num_from_user, int root_pid)
{
	struct task_struct *root_task_struct;
	int task_count;
	/* iterating just children should be DFS over every entry, 
	** TODO: next figure out
	** how to decide if a task is a process or thread 
	*/
	printk("root_pid is: %d", root_pid);
	root_task_struct = get_root(root_pid);
	if (root_task_struct == NULL){
		printk("Task returned null!\n");
		return -12;
	}

	task_count = iterate_siblings(root_task_struct);
	return task_count;
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
	//int cur_pid;
	//struct task_struct *root;
	//int task_count;

	// test vars:

	struct prinfo *kernel_buf, *bfs_queue;
	//struct prinfo task1, task2;
	struct kfifo buf_queue, queue;
	//int enq_ret;
	int ret;
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
	kernel_buf = kmalloc(sizeof(struct prinfo) * (num_from_user), GFP_KERNEL);
	if (kernel_buf == NULL){
		printk("ERROR: Failed to allocate kernel buffer!\n");
		return -11; //TODO: write down return values and their meanings, 11 is arbitrary
	}else
		printk("SUCCESS: allocated kernel buffer\n");

	printk("Allocating bfs_queue buffer, to same size as user\n");
	bfs_queue = kmalloc(sizeof(struct prinfo) * (num_from_user), GFP_KERNEL);
	if (bfs_queue == NULL){
		printk("ERROR: Failed to allocate bfs_queue buffer!\n");
		return -11; //TODO: write down return values and their meanings, 11 is arbitrary
	}else
		printk("SUCCESS: allocated bfs_queue buffer\n");

	/* Initializing kfifo using our buffer */
	ret = kfifo_init(&buf_queue, kernel_buf, sizeof(struct prinfo) * (*nr));
	printk("kfifo_init kernel_buf returned: %d", ret);

	/* Initializing another kfifo using for our BFS processing queue bfs_queue*/
	ret = kfifo_init(&queue, bfs_queue, sizeof(struct prinfo) * (*nr));
	printk("kfifo_init bfs_queue returned: %d", ret);

	/***
	   Enter the function that does all of the work
	   create lock here and isolate the critical space to just one function
	   enter_BFS() will do all of the work to keep the SYSCALL_DEFINE short
	   and to ensure that the lock is definetly being used correctly.
	***/
	read_lock(&tasklist_lock);
	printk("enter_BFS\n");
	//b = enter_BFS(kernel_buf, num_from_user, root_pid);
	//TODO TEST
	printk("enter test queue function\n");
		iterate_bfs_test(&buf_queue, &queue, root_pid);
	read_unlock(&tasklist_lock);
	printk("Done with enter_BFS function\n");

	//enq_ret = kfifo_in(&queue, &task1, sizeof(task1));
	//printk("kfifo enq returned: %d", enq_ret);

	/* once the buffer is set, copy to user */
	copy_to_user(buf, kernel_buf, sizeof(struct prinfo) * (*nr));

	kfree(kernel_buf);
	return 0;
}


