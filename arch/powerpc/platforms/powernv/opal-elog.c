/*
 * Error log support on PowerNV.
 *
 * Copyright 2013 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <asm/opal.h>

/* Maximum size of a single log on FSP is 16KB */
#define OPAL_MAX_ERRLOG_SIZE	16384

/* maximu number of records powernv can hold */
#define MAX_NUM_RECORD	128

struct opal_err_log {
	struct list_head link;
	uint64_t opal_log_id;
	size_t opal_log_size;
	uint8_t data[OPAL_MAX_ERRLOG_SIZE];
};

/* Pre-allocated temp buffer to pull error log from opal. */
static uint8_t err_log_data[OPAL_MAX_ERRLOG_SIZE];
/* Protect err_log_data buf */
static DEFINE_MUTEX(err_log_data_mutex);

static uint64_t total_log_size;
static bool opal_log_available;
static LIST_HEAD(elog_list);
static LIST_HEAD(elog_ack_list);

/* lock to protect elog_list and elog-ack_list. */
static DEFINE_SPINLOCK(opal_elog_lock);

static DECLARE_WAIT_QUEUE_HEAD(opal_log_wait);

/*
 * Interface for user to acknowledge the error log.
 *
 * Once user acknowledge the log, we delete that record entry from the
 * list and move it ack list.
 */
void opal_elog_ack(uint64_t ack_id)
{
	unsigned long flags;
	struct opal_err_log *record, *next;
	bool found = false;

	printk(KERN_INFO "OPAL Log ACK=%llx", ack_id);

	/* once user acknowledge a log delete record from list */
	spin_lock_irqsave(&opal_elog_lock, flags);
	list_for_each_entry_safe(record, next, &elog_list, link) {
		if (ack_id == record->opal_log_id) {
			list_del(&record->link);
			list_add(&record->link, &elog_ack_list);
			total_log_size -= OPAL_MAX_ERRLOG_SIZE;
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&opal_elog_lock, flags);

	/* Send acknowledgement to FSP */
	if (found)
		opal_send_ack_elog(ack_id);
	return;
}


static ssize_t elog_ack_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	uint32_t log_ack_id;
	log_ack_id = *(uint32_t *) buf;

	/* send acknowledgment to FSP */
	opal_elog_ack(log_ack_id);
	return 0;
}

/*
 * Show error log records to user.
 */
static ssize_t opal_elog_show(struct file *filp, struct kobject *kobj,
				struct bin_attribute *bin_attr, char *buf,
				loff_t pos, size_t count)
{
	unsigned long flags;
	struct opal_err_log *record, *next;
	size_t size = 0;
	size_t data_to_copy = 0;
	int error = 0;

	/* Display one log at a time. */
	if (count > OPAL_MAX_ERRLOG_SIZE)
		count = OPAL_MAX_ERRLOG_SIZE;

	spin_lock_irqsave(&opal_elog_lock, flags);
	/* Align the pos to point within total errlog size. */
	if (total_log_size && pos > total_log_size)
		pos = pos % total_log_size;

	/*
	 * if pos goes beyond total_log_size then we know we don't have any
	 * new record to show.
	 */
	if (total_log_size == 0 || pos >= total_log_size) {
		opal_log_available = 0;
		if (filp->f_flags & O_NONBLOCK) {
			spin_unlock_irqrestore(&opal_elog_lock, flags);
			error = -EAGAIN;
			goto out;
		}
		spin_unlock_irqrestore(&opal_elog_lock, flags);
		pos = 0;

		/* Wait until we get log from sapphire */
		error = wait_event_interruptible(opal_log_wait,
						 opal_log_available);
		if (error)
			goto out;
		spin_lock_irqsave(&opal_elog_lock, flags);
	}

	/*
	 * Show log record one by one through /sys/firmware/opal/opal_elog
	 */
	list_for_each_entry_safe(record, next, &elog_list, link) {
		if ((pos >= size) && (pos < (size + OPAL_MAX_ERRLOG_SIZE))) {
			data_to_copy = OPAL_MAX_ERRLOG_SIZE - (pos - size);
			if (count > data_to_copy)
				count = data_to_copy;
			memcpy(buf, record->data + (pos - size), count);
			error = count;
			break;
		}
		size += OPAL_MAX_ERRLOG_SIZE;
	}
	spin_unlock_irqrestore(&opal_elog_lock, flags);
out:
	return error;
}

/* Interface to read log from OPAL */
static void opal_elog_read(void)
{
	struct opal_err_log *record;
	size_t elog_size;
	uint64_t log_id;
	uint64_t elog_type;

	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(&opal_elog_lock, flags);
	if (list_empty(&elog_ack_list)) {
		/*
		 * We have no more room to read logs. Ignore it for now,
		 * will read it later when we have enough space.
		 */
		spin_unlock_irqrestore(&opal_elog_lock, flags);
		return;
	}

	/* Pull out the free node. */
	record = list_entry(elog_ack_list.next, struct opal_err_log, link);
	list_del(&record->link);
	spin_unlock_irqrestore(&opal_elog_lock, flags);

	/* read log size and log ID from OPAL */
	rc = opal_get_elog_size(&log_id, &elog_size, &elog_type);
	if (rc != OPAL_SUCCESS) {
		pr_err("ELOG: Opal log read failed\n");
		return;
	}
	if (elog_size >= OPAL_MAX_ERRLOG_SIZE)
		elog_size  =  OPAL_MAX_ERRLOG_SIZE;

	record->opal_log_id = log_id;
	record->opal_log_size = elog_size;
	memset(record->data, 0, sizeof(record->data));

	mutex_lock(&err_log_data_mutex);
	rc = opal_read_elog(__pa(err_log_data), elog_size, log_id);
	if (rc != OPAL_SUCCESS) {
		mutex_unlock(&err_log_data_mutex);
		pr_err("ELOG: log read failed for log-id=%llx\n", log_id);
		/* put back the free node. */
		spin_lock_irqsave(&opal_elog_lock, flags);
		list_add(&record->link, &elog_ack_list);
		spin_unlock_irqrestore(&opal_elog_lock, flags);
		return;
	}
	memcpy(record->data, err_log_data, elog_size);
	mutex_unlock(&err_log_data_mutex);

	spin_lock_irqsave(&opal_elog_lock, flags);
	list_add_tail(&record->link, &elog_list);
	total_log_size += OPAL_MAX_ERRLOG_SIZE;
	spin_unlock_irqrestore(&opal_elog_lock, flags);

	opal_log_available = 1;
	wake_up_interruptible(&opal_log_wait);
	return;
}

static void elog_work_fn(struct work_struct *work)
{
	opal_elog_read();
}

static DECLARE_WORK(elog_work, elog_work_fn);

static int elog_event(struct notifier_block *nb,
				unsigned long events, void *change)
{
	/* check for error log event */
	if (events & OPAL_EVENT_ERROR_LOG_AVAIL)
		schedule_work(&elog_work);
	return 0;
}

/* Initialize sysfs file */
static struct kobj_attribute opal_elog_ack_attr = __ATTR(opal_elog_ack,
						0200, NULL, elog_ack_store);

static struct notifier_block elog_nb = {
	.notifier_call  = elog_event,
	.next           = NULL,
	.priority       = 0
};

static struct bin_attribute opal_elog_attr = {
	.attr = {.name = "opal_elog", .mode = 0400},
	.read = opal_elog_show,
};

/*
 * Pre-allocate a buffer to hold handful of error logs until user space
 * consumes it.
 */
static int init_err_log_buffer(void)
{
	int i = 0;
	struct opal_err_log *buf_ptr;

	buf_ptr = vmalloc(sizeof(struct opal_err_log) * MAX_NUM_RECORD);
	if (!buf_ptr) {
		printk(KERN_ERR "ELOG: failed to allocate memory.\n");
		return -ENOMEM;
	}
	memset(buf_ptr, 0, sizeof(struct opal_err_log) * MAX_NUM_RECORD);

	/* Initialize ack list will all free nodes. */
	for (i = 0; i < MAX_NUM_RECORD; i++, buf_ptr++)
		list_add(&buf_ptr->link, &elog_ack_list);
	return 0;
}

/* Initialize error logging */
int __init opal_elog_init(void)
{
	int rc = 0;

	rc = init_err_log_buffer();
	if (rc)
		return rc;

	rc = sysfs_create_bin_file(opal_kobj, &opal_elog_attr);
	if (rc) {
		printk(KERN_ERR "ELOG: unable to create sysfs file"
					"opal_elog (%d)\n", rc);
		return rc;
	}

	rc = sysfs_create_file(opal_kobj, &opal_elog_ack_attr.attr);
	if (rc) {
		printk(KERN_ERR "ELOG: unable to create sysfs file"
			" opal_elog_ack (%d)\n", rc);
		return rc;
	}

	rc = opal_notifier_register(&elog_nb);
	if (rc) {
		pr_err("%s: Can't register OPAL event notifier (%d)\n",
		__func__, rc);
		return rc;
	}

	/* We are now ready to pull error logs from opal. */
	opal_resend_pending_logs();

	return 0;
}
