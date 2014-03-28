/*
 * PowerNV OPAL in-memory console interface
 *
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/opal.h>
#include <linux/debugfs.h>
#include <linux/of.h>
#include <linux/types.h>

/* OPAL in-memory console. Defined in OPAL source at core/console.c */
struct memcons {
	__be64 magic;
#define MEMCONS_MAGIC	0x6630696567726173L
	__be64 obuf_phys;
	__be64 ibuf_phys;
	__be32 obuf_size;
	__be32 ibuf_size;
	__be32 out_pos;
#define MEMCONS_OUT_POS_WRAP	0x80000000u
#define MEMCONS_OUT_POS_MASK	0x00ffffffu
	__be32 in_prod;
	__be32 in_cons;
};

static ssize_t opal_msglog_read(struct file *file, struct kobject *kobj,
				struct bin_attribute *bin_attr, char *to,
				loff_t pos, size_t count)
{
	struct memcons *mc = bin_attr->private;
	const char *conbuf;
	bool wrapped;
	size_t num_read;
	int out_pos;

	if (!mc)
		return -ENODEV;

	conbuf = phys_to_virt(be64_to_cpu(mc->obuf_phys));
	wrapped = be32_to_cpu(mc->out_pos) & MEMCONS_OUT_POS_WRAP;
	out_pos = be32_to_cpu(mc->out_pos) & MEMCONS_OUT_POS_MASK;

	if (!wrapped) {
		num_read = memory_read_from_buffer(to, count, &pos, conbuf,
				out_pos);
	} else {
		num_read = memory_read_from_buffer(to, count, &pos,
				conbuf + out_pos,
				be32_to_cpu(mc->obuf_size) - out_pos);

		if (num_read < 0)
			goto out;

		num_read += memory_read_from_buffer(to + num_read,
				count - num_read, &pos, conbuf, out_pos);
	}
out:
	return num_read;
}

static struct bin_attribute opal_msglog_attr = {
	.attr = {.name = "msglog", .mode = 0444},
	.read = opal_msglog_read
};

void __init opal_msglog_init(void)
{
	u64 mcaddr;
	struct memcons *mc;

	if (of_property_read_u64(opal_node, "ibm,opal-memcons", &mcaddr)) {
		pr_warn("OPAL: Property ibm,opal-memcons not found, no message log\n");
		return;
	}

	mc = phys_to_virt(mcaddr);
	if (!mc) {
		pr_warn("OPAL: memory console address is invalid\n");
		return;
	}

	if (be64_to_cpu(mc->magic) != MEMCONS_MAGIC) {
		pr_warn("OPAL: memory console version is invalid\n");
		return;
	}

	opal_msglog_attr.private = mc;

	if (sysfs_create_bin_file(opal_kobj, &opal_msglog_attr) != 0)
		pr_warn("OPAL: sysfs file creation failed\n");
}
