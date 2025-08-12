/*
 * ksight_platform.c
 *
 * Combined minimal platform driver + LSM hook module for ZCU104 FPGA co-processor.
 * - Platform driver: binds via device tree, maps regs, allocates DMA-coherent ring
 *   buffer and exposes its physical address via sysfs.
 * - LSM: registers socket recv/send hooks and emits tag_event entries into the
 *   DMA ring buffer (if allocated).
 *
 * Kernel: tested conceptually for 6.1 (PetaLinux 2023.1). Adapt file-read hooks
 * and tag lookups to your system.
 *
 * Build as out-of-tree module against matching kernel headers.
 */

#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/uio.h>


#define RING_SIZE 4096   /* events */
#define DEVICE_NAME "ksight"
#define DRIVER_NAME "ksight"


/* Flag indicating whether initialization completed */
int safesetid_initialized __initdata;

/* Event structure sent to FPGA */
struct tag_event {
	u32 pid;
	u32 tid;
	u64 timestamp_ns;
	unsigned long addr_start;
	unsigned long addr_end;
	u32 tag_id;
	u32 op_type;    /* 0=read,1=write,2=recv,3=send */
} __packed;

/* Check for alignment */
static_assert(sizeof(struct tag_event) % 8 == 0);

/* Ring buffer layout in DMA memory */
struct ring_buffer {
    /* producer writes events at head, FPGA/consumer reads from tail.
	 * We only store head in kernel; tail is managed/observed by FPGA or driver.
	 */
	u32 head;
	u32 reserved;
	struct tag_event buffer[RING_SIZE];
};

static struct ring_buffer *ring;         /* kernel virtual pointer */
static dma_addr_t ring_dma_handle;       /* physical/DMA address */
static struct device *gdev;              /* platform device's device */
static void __iomem *regs_base;          /* mapped FPGA regs (if any) */
static int g_irq = -1;

/* Simple push: non-blocking, drop on full.
 * The ring consumer (FPGA) must update tail in hardware/registers or via IRQs.
 */
static void push_tag_event(const struct tag_event *ev)
{
	unsigned long flags;
	u32 next;

	if (!ring)
		return;

	/* We protect head only in kernel domain. Tail is unknown here; to
	 * detect full/overflow we'd need to read tail (from FPGA via regs).
	 * For simplicity, detect simple overflow by checking next == 0 and
	 * allow wrap — accept possibility of overwrite if consumer lags.
	 *
	 * Production: read tail via ioread32(regs_tail) and avoid overwriting.
	 */
	local_irq_save(flags);
	next = ring->head + 1;
	if (next >= RING_SIZE)
		next = 0;

	/* Write event at current head */
	memcpy(&ring->buffer[ring->head], ev, sizeof(*ev));
	/* publish new head */
	smp_wmb();                    /* ensure event data visible before head update */
	ring->head = next;
	local_irq_restore(flags);
}

/* -----------------------
 * LSM hook implementations
 * -----------------------
 *
 * Minimal examples of LSM hooks for read/write and send/recv.
 * For file read/write you should implement file_read_iter/file_write_iter
 * hooks with careful handling of scatter/gather iov_iter cases.
 */

/* socket_recvmsg: called after the kernel receives into the buffer.
 */
static int ksight_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				 int size, int flags)
{
	struct tag_event ev;
	struct iovec iov;

	if (!msg || !msg->msg_iter.count || msg->msg_iter.count == 0)
		return 0;

	ev.pid = (u32)task_pid_nr(current);
	ev.tid = (u32)task_tgid_nr(current);
	ev.timestamp_ns = ktime_get_ns();
	ev.addr_start = (unsigned long)iov.iov_base;
	ev.addr_end = ev.addr_start + size;
	ev.tag_id = 0x00000001;
	ev.op_type = 2; /* recv */

	push_tag_event(&ev);
	return 0;
}

/* Register only the most relevant hooks you need. Add file_read_iter/file_write_iter
 * hooks later once you implement correct iov_iter parsing and tag lookup.
 */
static struct security_hook_list ksight_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(socket_recvmsg, ksight_socket_recvmsg),
};
