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

/* socket_sendmsg: called before kernel sends from user buffer.
 */
static int ksight_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				 int size)
{
	struct tag_event ev;
	struct iovec iov;

	if (!msg || !msg->msg_iter.count || msg->msg_iter.count == 0)
		return 0;

	iov = iov_iter_iovec(&msg->msg_iter);

	ev.pid = (u32)task_pid_nr(current);
	ev.tid = (u32)task_tgid_nr(current);
	ev.timestamp_ns = ktime_get_ns();
	ev.addr_start = (unsigned long)iov.iov_base;
	ev.addr_end = ev.addr_start + iov.iov_len;
	ev.tag_id = 0x00000001;
	ev.op_type = 3; /* send */

	push_tag_event(&ev);
	return 0;
}

/* Register only the most relevant hooks you need. Add file_read_iter/file_write_iter
 * hooks later once you implement correct iov_iter parsing and tag lookup.
 */
static struct security_hook_list ksight_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(socket_recvmsg, ksight_socket_recvmsg),
	LSM_HOOK_INIT(socket_sendmsg, ksight_socket_sendmsg),
};

/* -----------------------
 * Platform driver
 * -----------------------
 */

static ssize_t ring_phys_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	if (!ring)
		return sprintf(buf, "0\n");
	return sprintf(buf, "0x%pad\n", &ring_dma_handle);
}
static DEVICE_ATTR_RO(ring_phys);

/* Interruption request handler */
static irqreturn_t ksight_irq_handler(int irq, void *dev_id)
{
	/* TODO: handle FPGA -> CPU interrupts (e.g., tail update, wakeups) */
	/* TODO: Clear IRQ in FPGA registers. */
	return IRQ_HANDLED;
}

/* Allocate DMA-coherent ring buffer */
static int allocate_ring_buffer(struct device *dev)
{
	size_t size = sizeof(struct ring_buffer);

	ring = dma_alloc_coherent(dev, size, &ring_dma_handle, GFP_KERNEL);
	if (!ring)
		return -ENOMEM;

	/* zero and init */
	memset(ring, 0, size);
	/* initial head = 0; already zeroed */
	dev_info(dev, "ring allocated virt=%p phys=%pad size=%zu\n",
		 ring, &ring_dma_handle, size);
	return 0;
}

static void free_ring_buffer(struct device *dev)
{
	if (!ring)
		return;
	dma_free_coherent(dev, sizeof(struct ring_buffer), ring, ring_dma_handle);
	ring = NULL;
	ring_dma_handle = 0;
}

/* Platform probe: map regs, allocate ring, create sysfs attr, request IRQ if present */
static int ksight_platform_driver_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct resource *res;

	gdev = &pdev->dev;

	/* TODO: map registers */
	// res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	// if (res) {
	// 	regs_base = devm_ioremap_resource(gdev, res);
	// 	if (IS_ERR(regs_base)) {
	// 		dev_err(gdev, "failed to map regs\n");
	// 		return PTR_ERR(regs_base);
	// 	}
	// 	dev_info(gdev, "regs mapped at %p\n", regs_base);
	// }

	/* allocate ring buffer DMA memory tied to this device */
	ret = allocate_ring_buffer(gdev);
	if (ret) {
		dev_err(gdev, "dma allocation failed: %d\n", ret);
		return ret;
	}

	/* export physical address to userspace via sysfs attr */
	ret = device_create_file(gdev, &dev_attr_ring_phys);
	if (ret) {
		dev_err(gdev, "failed to create sysfs attr\n");
		free_ring_buffer(gdev);
		return ret;
	}

	/* TODO: request IRQ */
	// g_irq = platform_get_irq(pdev, 0);
	// if (g_irq > 0) {
	// 	ret = devm_request_irq(gdev, g_irq, ksight_irq_handler, 0,
	// 			       dev_name(gdev), NULL);
	// 	if (ret) {
	// 		dev_warn(gdev, "request_irq failed: %d\n", ret);
	// 		/* non-fatal: continue without IRQ */
	// 	} else {
	// 		dev_info(gdev, "irq %d registered\n", g_irq);
	// 	}
	// }

	dev_info(gdev, "probe completed: ring phys at 0x%pad\n", &ring_dma_handle);
	return 0;
}

static int ksight_platform_driver_remove(struct platform_device *pdev)
{
	/* remove sysfs entry first */
	device_remove_file(&pdev->dev, &dev_attr_ring_phys);

	/* free ring and other resources */
	free_ring_buffer(&pdev->dev);

	/* devm_ioremap_resource and devm_request_irq are freed automatically */
	dev_info(&pdev->dev, "removed\n");
	return 0;
}


/**
 * Open Firmware Device Identifier Matching Table
 */
static const struct of_device_id ksight_of_match[] = {
	{ .compatible = "sushi,ksight", },
	{ /* end of table */ }
};
MODULE_DEVICE_TABLE(of, ksight_of_match);

/**
 * Platform Driver Structure
 */
static struct platform_driver ksight_platform_driver = {
	.probe = ksight_platform_driver_probe,
	.remove = ksight_platform_driver_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = DRIVER_NAME,
		.of_match_table = ksight_of_match,
	},
};

/* -----------------------
 * Module init / exit
 * -----------------------
 */

static int __init ksight_init(void)
{
	int ret;

	/* register platform driver (probe will allocate DMA ring when device present) */
	ret = platform_driver_register(&ksight_platform_driver);
	if (ret) {
		pr_err("platform_driver_register failed: %d\n", ret);
		return ret;
	}

	/* register LSM hooks (once registered, not easily unregisterable).
	 * Hooks must exist before kernel security checks if required.
	 */
	security_add_hooks(ksight_hooks, ARRAY_SIZE(ksight_hooks), "ksight");

	pr_info("ksight:: module initialized\n");
	return 0;
}

static void __exit ksight_exit(void)
{
	/* platform driver unregister; if probe allocated ring, remove will free it. */
	platform_driver_unregister(&ksight_platform_driver);
	pr_info("ksight: module exiting\n");
}

module_init(ksight_init);
module_exit(ksight_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Platform driver & LSM hooks for FPGA DIFT co-processor Hardblare-NG");
