/*
 * PowerNV OPAL Dump Interface
 *
 * Copyright 2013 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kobject.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/delay.h>

#include <asm/opal.h>

/* Dump type */
#define DUMP_TYPE_FSP	0x01

/* Extract failed */
#define DUMP_NACK_ID	0x00

/* Dump record */
struct dump_record {
	uint8_t		type;
	uint32_t	id;
	uint32_t	size;
	char		*buffer;
};
static struct dump_record dump_record;

/* Dump available status */
static u32 dump_avail;

/* Binary blobs */
static struct debugfs_blob_wrapper dump_blob;
static struct debugfs_blob_wrapper readme_blob;

/* Ignore dump notification, if we fail to create debugfs files */
static bool dump_disarmed = false;


static void free_dump_sg_list(struct opal_sg_list *list)
{
	struct opal_sg_list *sg1;
	while (list) {
		sg1 = list->next;
		kfree(list);
		list = sg1;
	}
	list = NULL;
}

/*
 * Build dump buffer scatter gather list
 */
static struct opal_sg_list *dump_data_to_sglist(void)
{
	struct opal_sg_list *sg1, *list = NULL;
	void *addr;
	int64_t size;

	addr = dump_record.buffer;
	size = dump_record.size;

	sg1 = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sg1)
		goto nomem;

	list = sg1;
	sg1->num_entries = 0;
	while (size > 0) {
		/* Translate virtual address to physical address */
		sg1->entry[sg1->num_entries].data =
			(void *)(vmalloc_to_pfn(addr) << PAGE_SHIFT);

		if (size > PAGE_SIZE)
			sg1->entry[sg1->num_entries].length = PAGE_SIZE;
		else
			sg1->entry[sg1->num_entries].length = size;

		sg1->num_entries++;
		if (sg1->num_entries >= SG_ENTRIES_PER_NODE) {
			sg1->next = kzalloc(PAGE_SIZE, GFP_KERNEL);
			if (!sg1->next)
				goto nomem;

			sg1 = sg1->next;
			sg1->num_entries = 0;
		}
		addr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
	return list;

nomem:
	pr_err("%s : Failed to allocate memory\n", __func__);
	free_dump_sg_list(list);
	return NULL;
}

/*
 * Translate sg list address to absolute
 */
static void sglist_to_phy_addr(struct opal_sg_list *list)
{
	struct opal_sg_list *sg, *next;

	for (sg = list; sg; sg = next) {
		next = sg->next;
		/* Don't translate NULL pointer for last entry */
		if (sg->next)
			sg->next = (struct opal_sg_list *)__pa(sg->next);
		else
			sg->next = NULL;

		/* Convert num_entries to length */
		sg->num_entries =
			sg->num_entries * sizeof(struct opal_sg_entry) + 16;
	}
}

static void free_dump_data_buf(void)
{
	vfree(dump_record.buffer);
	dump_record.size = 0;
}

/*
 * Allocate dump data buffer.
 */
static int alloc_dump_data_buf(void)
{
	dump_record.buffer = vzalloc(PAGE_ALIGN(dump_record.size));
	if (!dump_record.buffer) {
		pr_err("%s : Failed to allocate memory\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

/*
 * Initiate FipS dump
 */
static int64_t dump_fips_init(uint8_t type)
{
	int rc;

	rc = opal_dump_init(type);
	if (rc)
		pr_warn("%s: Failed to initiate FipS dump (%d)\n",
			__func__, rc);
	return rc;
}

/*
 * Get dump ID and size.
 */
static int64_t dump_read_info(void)
{
	int rc;

	rc = opal_dump_info(&dump_record.id, &dump_record.size);
	if (rc)
		pr_warn("%s: Failed to get dump info (%d)\n",
			__func__, rc);
	return rc;
}

/*
 * Send acknoledgement to OPAL
 */
static int64_t dump_send_ack(uint32_t dump_id)
{
	int rc;

	rc = opal_dump_ack(dump_id);
	if (rc)
		pr_warn("%s: Failed to send ack message to ID 0x%x (%d)\n",
			__func__, dump_id, rc);
	return rc;
}

/*
 * Retrieve dump data
 */
static int64_t dump_read_data(void)
{
	struct opal_sg_list *list;
	uint64_t addr;
	int64_t rc;

	/* Allocate memory */
	rc = alloc_dump_data_buf();
	if (rc)
		goto out;

	/* Generate SG list */
	list = dump_data_to_sglist();
	if (!list) {
		rc = -ENOMEM;
		goto out;
	}

	/* Translate sg list addr to real address */
	sglist_to_phy_addr(list);

	/* First entry address */
	addr = __pa(list);

	/* Fetch data */
	rc = OPAL_BUSY;
	while (rc == OPAL_BUSY || rc == OPAL_BUSY_EVENT) {
		rc = opal_dump_read(dump_record.id, addr);
		if (rc == OPAL_BUSY) {
			opal_poll_events(NULL);
			mdelay(10);
		}
	}

	if (rc != OPAL_SUCCESS && rc != OPAL_PARTIAL)
		pr_warn("%s: Extract dump failed for ID 0x%x\n",
			__func__, dump_record.id);

	/* Free SG list */
	free_dump_sg_list(list);

out:
	return rc;
}

static int extract_dump(void)
{
	int rc;

	/* Get dump ID, size */
	rc = dump_read_info();
	if (rc != OPAL_SUCCESS)
		return rc;

	/* Read dump data */
	rc = dump_read_data();
	if (rc != OPAL_SUCCESS && rc != OPAL_PARTIAL) {
		/*
		 * Failed to allocate memory to retrieve dump. Lets send
		 * negative ack so that we get notification again.
		 */
		dump_send_ack(DUMP_NACK_ID);

		/* Free dump buffer */
		free_dump_data_buf();

		return rc;
	}
	if (rc == OPAL_PARTIAL)
		pr_info("%s: Partially read dump ID 0x%x\n",
			__func__, dump_record.id);

	pr_info("%s: New platform dump available. ID = 0x%x\n",
		__func__, dump_record.id);

	/* Update dump blob */
	dump_blob.data = (void *)dump_record.buffer;
	dump_blob.size = dump_record.size;

	/* Update dump available status */
	dump_avail = 1;

	return rc;
}

static void dump_extract_fn(struct work_struct *work)
{
	extract_dump();
}

static DECLARE_WORK(dump_work, dump_extract_fn);

/* Workqueue to extract dump */
static void schedule_extract_dump(void)
{
	schedule_work(&dump_work);
}

/*
 * New dump available notification
 *
 * Once we get notification, we extract dump via OPAL call
 * and then write dump to file.
 */
static int dump_event(struct notifier_block *nb,
		      unsigned long events, void *change)
{
	/*
	 * Don't retrieve dump, if we don't have debugfs
	 * interface to pass data to userspace.
	 */
	if (dump_disarmed)
		return 0;

	/* Check for dump available notification */
	if (events & OPAL_EVENT_DUMP_AVAIL)
		schedule_extract_dump();

	return 0;
}

static struct notifier_block dump_nb = {
	.notifier_call  = dump_event,
	.next           = NULL,
	.priority       = 0
};


/* FIXME: debugfs README message */
static const char readme_msg[] =
	"This file will be populated shortly..";

/* debugfs dump_control file operations */
static ssize_t dump_control_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[4];
	size_t buf_size;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;

	switch (buf[0]) {
	case '1':	/* Dump send ack */
		if(dump_avail) {
			dump_avail = 0;
			free_dump_data_buf();
			dump_send_ack(dump_record.id);
		}
		break;
	case '2':	/* Initiate FipS dump */
		dump_fips_init(DUMP_TYPE_FSP);
		break;
	default:
		break;
	}
	return count;
}

static const struct file_operations dump_control_fops = {
	.open	= simple_open,
	.write	= dump_control_write,
	.llseek	= default_llseek,
};

/*
 * Create dump debugfs file
 */
static int debugfs_dump_init(void)
{
	struct dentry *dir, *file;

	/* FSP dump directory */
	dir = debugfs_create_dir("fsp", NULL);
	if (!dir)
		goto out;

	/* README */
	readme_blob.data = (void *)readme_msg;
	readme_blob.size = strlen(readme_msg);
	file = debugfs_create_blob("README", 0400, dir, &readme_blob);
	if (!file)
		goto remove_dir;

	/* Dump available notification */
	file = debugfs_create_u32("dump_avail", 0400, dir, &dump_avail);
	if (!file)
		goto remove_dir;

	/* data file */
	dump_blob.data = (void *)dump_record.buffer;
	dump_blob.size = dump_record.size;
	file = debugfs_create_blob("dump", 0400, dir, &dump_blob);
	if (!file)
		goto remove_dir;

	/* Control file */
	file = debugfs_create_file("dump_control", 0200, dir,
				   NULL, &dump_control_fops);
	if (!file)
		goto remove_dir;

	return 0;

remove_dir:
	debugfs_remove_recursive(dir);

out:
	dump_disarmed = true;
	return -1;
}

void __init opal_platform_dump_init(void)
{
	int ret;

	/* Register for opal notifier */
	ret = opal_notifier_register(&dump_nb);
	if (ret) {
		pr_warn("%s: Can't register OPAL event notifier (%d)\n",
			__func__, ret);
		return;
	}

	/* debugfs interface */
	ret = debugfs_dump_init();
}
