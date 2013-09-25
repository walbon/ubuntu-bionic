/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright 2010 Paul Mackerras, IBM Corp. <paulus@au1.ibm.com>
 * Copyright 2011 David Gibson, IBM Corporation <dwg@au1.ibm.com>
 * Copyright 2013 Alexey Kardashevskiy, IBM Corporation <aik@au1.ibm.com>
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/list.h>
#include <linux/anon_inodes.h>
#include <linux/module.h>
#include <linux/vfio.h>
#include <linux/iommu.h>
#include <linux/file.h>

#include <asm/tlbflush.h>
#include <asm/kvm_ppc.h>
#include <asm/kvm_book3s.h>
#include <asm/mmu-hash64.h>
#include <asm/hvcall.h>
#include <asm/synch.h>
#include <asm/ppc-opcode.h>
#include <asm/kvm_host.h>
#include <asm/udbg.h>
#include <asm/iommu.h>
#include <asm/tce.h>

#define ERROR_ADDR      ((void *)~(unsigned long)0x0)

/*
 * Dynamically linked version of the external user VFIO API.
 *
 * As a IOMMU group access control is implemented by VFIO,
 * there is some API to vefiry that specific process can own
 * a group. As KVM may run when VFIO is not loaded, KVM is not
 * linked statically to VFIO, instead wrappers are used.
 */
struct vfio_group *kvmppc_vfio_group_get_external_user(struct file *filep)
{
	struct vfio_group *ret;
	struct vfio_group * (*proc)(struct file *) =
			symbol_get(vfio_group_get_external_user);
	if (!proc)
		return NULL;

	ret = proc(filep);
	symbol_put(vfio_group_get_external_user);

	return ret;
}

void kvmppc_vfio_group_put_external_user(struct vfio_group *group)
{
	void (*proc)(struct vfio_group *) =
			symbol_get(vfio_group_put_external_user);
	if (!proc)
		return;

	proc(group);
	symbol_put(vfio_group_put_external_user);
}

int kvmppc_vfio_external_user_iommu_id(struct vfio_group *group)
{
	int ret;
	int (*proc)(struct vfio_group *) =
			symbol_get(vfio_external_user_iommu_id);
	if (!proc)
		return -EINVAL;

	ret = proc(group);
	symbol_put(vfio_external_user_iommu_id);

	return ret;
}

static long kvmppc_stt_npages(unsigned long window_size)
{
	return ALIGN((window_size >> SPAPR_TCE_SHIFT)
		     * sizeof(u64), PAGE_SIZE) / PAGE_SIZE;
}

static void release_spapr_tce_table(struct kvmppc_spapr_tce_table *stt)
{
	struct kvm *kvm = stt->kvm;
	int i;

	mutex_lock(&kvm->lock);
	list_del(&stt->list);
	for (i = 0; i < kvmppc_stt_npages(stt->window_size); i++)
		__free_page(stt->pages[i]);
	kfree(stt);
	mutex_unlock(&kvm->lock);

	kvm_put_kvm(kvm);
}

static int kvm_spapr_tce_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kvmppc_spapr_tce_table *stt = vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff >= kvmppc_stt_npages(stt->window_size))
		return VM_FAULT_SIGBUS;

	page = stt->pages[vmf->pgoff];
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct kvm_spapr_tce_vm_ops = {
	.fault = kvm_spapr_tce_fault,
};

static int kvm_spapr_tce_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &kvm_spapr_tce_vm_ops;
	return 0;
}

static int kvm_spapr_tce_release(struct inode *inode, struct file *filp)
{
	struct kvmppc_spapr_tce_table *stt = filp->private_data;

	release_spapr_tce_table(stt);
	return 0;
}

static const struct file_operations kvm_spapr_tce_fops = {
	.mmap           = kvm_spapr_tce_mmap,
	.release	= kvm_spapr_tce_release,
};

long kvm_vm_ioctl_create_spapr_tce(struct kvm *kvm,
				   struct kvm_create_spapr_tce *args)
{
	struct kvmppc_spapr_tce_table *stt = NULL;
	long npages;
	int ret = -ENOMEM;
	int i;

	/* Check this LIOBN hasn't been previously allocated */
	if (kvmppc_find_tce_table(kvm, args->liobn))
		return -EBUSY;

	npages = kvmppc_stt_npages(args->window_size);

	stt = kzalloc(sizeof(*stt) + npages * sizeof(struct page *),
		      GFP_KERNEL);
	if (!stt)
		goto fail;

	stt->type = KVMPPC_TCET_EMULATED;
	stt->liobn = args->liobn;
	stt->window_size = args->window_size;
	stt->kvm = kvm;

	for (i = 0; i < npages; i++) {
		stt->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!stt->pages[i])
			goto fail;
	}

	kvm_get_kvm(kvm);

	mutex_lock(&kvm->lock);
	list_add(&stt->list, &kvm->arch.spapr_tce_tables);

	mutex_unlock(&kvm->lock);

	return anon_inode_getfd("kvm-spapr-tce", &kvm_spapr_tce_fops,
				stt, O_RDWR);

fail:
	if (stt) {
		for (i = 0; i < npages; i++)
			if (stt->pages[i])
				__free_page(stt->pages[i]);

		kfree(stt);
	}
	return ret;
}

static void kvmppc_spapr_tce_iommu_table_destroy(
		struct kvm_device *dev,
		struct kvmppc_spapr_tce_table *tt)
{
	struct kvm *kvm = dev->kvm;

	mutex_lock(&kvm->lock);
	list_del(&tt->list);

	if (tt->vfio_grp)
		kvmppc_vfio_group_put_external_user(tt->vfio_grp);
	iommu_group_put(tt->grp);

	kfree(tt);
	mutex_unlock(&kvm->lock);
}

static int kvmppc_spapr_tce_iommu_create(struct kvm_device *dev, u32 type)
{
	struct kvmppc_spapr_tce_iommu_device *tcedev;
	int ret = 0;

	tcedev = kzalloc(sizeof(*tcedev), GFP_KERNEL);
	if (!tcedev)
		return -ENOMEM;
	dev->private = tcedev;

	INIT_LIST_HEAD(&tcedev->tables);

	/* Already there ? */
	mutex_lock(&dev->kvm->lock);
	if (dev->kvm->arch.tcedev)
		ret = -EEXIST;
	else
		dev->kvm->arch.tcedev = tcedev;
	mutex_unlock(&dev->kvm->lock);

	if (ret)
		kfree(tcedev);

	return ret;
}

static long kvmppc_spapr_tce_iommu_link(struct kvm_device *dev,
		u64 liobn, u32 group_fd)
{
	struct kvmppc_spapr_tce_iommu_device *tcedev = dev->private;
	struct kvmppc_spapr_tce_table *tt;
	struct iommu_group *grp;
	struct iommu_table *tbl;
	struct file *vfio_filp;
	struct vfio_group *vfio_grp;
	int ret = -ENXIO, iommu_id;

	/* Check this LIOBN hasn't been previously registered */
	tt = kvmppc_find_tce_table(dev->kvm, liobn);
	if (tt) {
		if (group_fd != -1)
			return -EBUSY;

		tt = kvmppc_find_iommu_tce_table(dev->kvm, liobn);
		if (tt) {
			kvmppc_spapr_tce_iommu_table_destroy(dev, tt);
			return 0;
		}
		return -EINVAL;
	}

	vfio_filp = fget(group_fd);
	if (!vfio_filp)
		return -ENXIO;

	/*
	 * Lock the group. Fails if group is not viable or
	 * does not have IOMMU set
	 */
	vfio_grp = kvmppc_vfio_group_get_external_user(vfio_filp);
	if (IS_ERR_VALUE((unsigned long)vfio_grp))
		goto fput_exit;

	/* Get IOMMU ID, find iommu_group and iommu_table*/
	iommu_id = kvmppc_vfio_external_user_iommu_id(vfio_grp);
	if (iommu_id < 0)
		goto grpput_fput_exit;

	grp = iommu_group_get_by_id(iommu_id);
	if (!grp)
		goto grpput_fput_exit;

	tbl = iommu_group_get_iommudata(grp);
	if (!tbl)
		goto grpput_fput_exit;

	/* Create a TCE table descriptor and add into the descriptor list */
	tt = kzalloc(sizeof(*tt), GFP_KERNEL);
	if (!tt)
		goto grpput_fput_exit;

	tt->type = KVMPPC_TCET_IOMMU;
	tt->liobn = liobn;
	tt->grp = grp;
	tt->window_size = tbl->it_size << IOMMU_PAGE_SHIFT;
	tt->vfio_grp = vfio_grp;

	/* Add the TCE table descriptor to the descriptor list */
	mutex_lock(&dev->kvm->lock);
	list_add(&tt->list, &tcedev->tables);
	mutex_unlock(&dev->kvm->lock);

	ret = 0;

	goto fput_exit;

grpput_fput_exit:
	kvmppc_vfio_group_put_external_user(vfio_grp);
fput_exit:
	fput(vfio_filp);

	return ret;
}

static int kvmppc_spapr_tce_iommu_set_attr(struct kvm_device *dev,
		struct kvm_device_attr *attr)
{
	u32 group_fd;
	u32 __user *argp = (u32 __user *) attr->addr;

	switch (attr->group) {
	case KVM_DEV_SPAPR_TCE_IOMMU_ATTR_LINKAGE:
		if (get_user(group_fd, argp))
			return -EFAULT;

		return kvmppc_spapr_tce_iommu_link(dev, attr->attr, group_fd);
	}
	return -ENXIO;
}

static int kvmppc_spapr_tce_iommu_has_attr(struct kvm_device *dev,
		struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_SPAPR_TCE_IOMMU_ATTR_LINKAGE:
		return 0;
	}
	return -ENXIO;
}

static void kvmppc_spapr_tce_iommu_destroy(struct kvm_device *dev)
{
	struct kvmppc_spapr_tce_iommu_device *tcedev = dev->private;
	struct kvmppc_spapr_tce_table *tt, *tmp;

	list_for_each_entry_safe(tt, tmp, &tcedev->tables, list) {
		kvmppc_spapr_tce_iommu_table_destroy(dev, tt);
	}
	kfree(tcedev);
	kfree(dev);
}

struct kvm_device_ops kvmppc_spapr_tce_iommu_ops = {
	.name = "kvm-spapr-tce-iommu",
	.create = kvmppc_spapr_tce_iommu_create,
	.set_attr = kvmppc_spapr_tce_iommu_set_attr,
	.has_attr = kvmppc_spapr_tce_iommu_has_attr,
	.destroy = kvmppc_spapr_tce_iommu_destroy,
};

/*
 * Converts guest physical address to host virtual address.
 * Also returns host physical address which is to put to TCE table.
 */
static void __user *kvmppc_gpa_to_hva_and_get(struct kvm_vcpu *vcpu,
		unsigned long gpa, struct page **pg, unsigned long *phpa)
{
	unsigned long hva, gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot;
	const int is_write = 0;

	memslot = search_memslots(kvm_memslots(vcpu->kvm), gfn);
	if (!memslot)
		return ERROR_ADDR;

	hva = __gfn_to_hva_memslot(memslot, gfn) | (gpa & ~PAGE_MASK);

	if (get_user_pages_fast(hva & PAGE_MASK, 1, is_write, pg) != 1)
		return ERROR_ADDR;

	if (phpa)
		*phpa = __pa((unsigned long) page_address(*pg)) |
				(hva & ~PAGE_MASK);

	return (void *) hva;
}

long kvmppc_h_put_tce_iommu(struct kvm_vcpu *vcpu,
		struct kvmppc_spapr_tce_table *tt,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce)
{
	struct page *pg = NULL;
	unsigned long hpa;
	void __user *hva;
	struct iommu_table *tbl = iommu_group_get_iommudata(tt->grp);

	if (!tbl)
		return H_RESCINDED;

	/* Clear TCE */
	if (!(tce & (TCE_PCI_READ | TCE_PCI_WRITE))) {
		if (iommu_tce_clear_param_check(tbl, ioba, 0, 1))
			return H_PARAMETER;

		if (iommu_free_tces(tbl, ioba >> IOMMU_PAGE_SHIFT,
				1, false))
			return H_HARDWARE;

		return H_SUCCESS;
	}

	/* Put TCE */

	/* Real mode referenced the page but hpte changed during this operation */
	if (vcpu->arch.tce_rm_fail == TCERM_GETPAGE) {
		put_page(pfn_to_page(vcpu->arch.tce_tmp_hpas[0] >> PAGE_SHIFT));
		/* And try again */
	}
	vcpu->arch.tce_rm_fail = TCERM_NONE;

	if (iommu_tce_put_param_check(tbl, ioba, tce))
		return H_PARAMETER;

	hva = kvmppc_gpa_to_hva_and_get(vcpu, tce, &pg, &hpa);
	if (hva == ERROR_ADDR)
		return H_HARDWARE;

	if (!iommu_tce_build(tbl, ioba >> IOMMU_PAGE_SHIFT, &hpa, 1, false))
		return H_SUCCESS;

	if (pg)
		put_page(pg);

	return H_HARDWARE;
}

static long kvmppc_h_put_tce_indirect_iommu(struct kvm_vcpu *vcpu,
		struct kvmppc_spapr_tce_table *tt, unsigned long ioba,
		unsigned long __user *tces, unsigned long npages)
{
	long i;
	struct iommu_table *tbl = iommu_group_get_iommudata(tt->grp);

	if (!tbl)
		return H_RESCINDED;

	if (vcpu->arch.tce_rm_fail == TCERM_GETPAGE) {
		unsigned long tmp = vcpu->arch.tce_tmp_hpas[vcpu->arch.tce_tmp_num];
		put_page(pfn_to_page(tmp >> PAGE_SHIFT));
	}

	for (i = vcpu->arch.tce_tmp_num; i < npages; ++i) {
		struct page *pg = NULL;
		unsigned long gpa;
		void __user *hva;

		if (get_user(gpa, tces + i))
			return H_HARDWARE;

		if (iommu_tce_put_param_check(tbl, ioba +
					(i << IOMMU_PAGE_SHIFT), gpa))
			return H_PARAMETER;

		hva = kvmppc_gpa_to_hva_and_get(vcpu, gpa, &pg,
				&vcpu->arch.tce_tmp_hpas[i]);
		if (hva == ERROR_ADDR)
			goto putpages_flush_exit;
	}

	if (!iommu_tce_build(tbl, ioba >> IOMMU_PAGE_SHIFT,
			vcpu->arch.tce_tmp_hpas, npages, false))
		return H_SUCCESS;

putpages_flush_exit:
	for (--i; i >= 0; --i) {
		struct page *pg;
		pg = pfn_to_page(vcpu->arch.tce_tmp_hpas[i] >> PAGE_SHIFT);
		if (pg)
			put_page(pg);
	}

	return H_HARDWARE;
}

long kvmppc_h_stuff_tce_iommu(struct kvm_vcpu *vcpu,
		struct kvmppc_spapr_tce_table *tt,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct iommu_table *tbl = iommu_group_get_iommudata(tt->grp);
	unsigned long entry = ioba >> IOMMU_PAGE_SHIFT;

	if (!tbl)
		return H_RESCINDED;

	if (iommu_tce_clear_param_check(tbl, ioba, tce_value, npages))
		return H_PARAMETER;

	if (iommu_free_tces(tbl, entry, npages, false))
		return H_HARDWARE;

	return H_SUCCESS;
}

long kvmppc_h_put_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce)
{
	long ret;
	struct kvmppc_spapr_tce_table *tt;

	tt = kvmppc_find_tce_table(vcpu->kvm, liobn);
	if (!tt)
		return H_TOO_HARD;

	if (tt->type == KVMPPC_TCET_IOMMU)
		return kvmppc_h_put_tce_iommu(vcpu, tt, liobn, ioba, tce);

	/* Emulated IO */
	if (ioba >= tt->window_size)
		return H_PARAMETER;

	ret = kvmppc_tce_validate(tce);
	if (ret)
		return ret;

	kvmppc_tce_put(tt, ioba, tce);

	return H_SUCCESS;
}

long kvmppc_h_put_tce_indirect(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_list, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *tt;
	long i, ret = H_SUCCESS;
	unsigned long __user *tces;
	struct page *pg = NULL;

	tt = kvmppc_find_tce_table(vcpu->kvm, liobn);
	if (!tt)
		return H_TOO_HARD;

	/*
	 * The spec says that the maximum size of the list is 512 TCEs
	 * so the whole table addressed resides in 4K page
	 */
	if (npages > 512)
		return H_PARAMETER;

	if (tce_list & ~IOMMU_PAGE_MASK)
		return H_PARAMETER;

	if ((ioba + (npages << IOMMU_PAGE_SHIFT)) > tt->window_size)
		return H_PARAMETER;

	if (vcpu->arch.tce_rm_fail != TCERM_NONE)
		put_page(pfn_to_page(tce_list >> PAGE_SHIFT));

	if (vcpu->arch.tce_rm_fail == TCERM_PUTLISTPAGE)
		return H_SUCCESS;

	tces = kvmppc_gpa_to_hva_and_get(vcpu, tce_list, &pg, NULL);
	if (tces == ERROR_ADDR)
		return H_TOO_HARD;

	if (tt->type == KVMPPC_TCET_IOMMU) {
		ret = kvmppc_h_put_tce_indirect_iommu(vcpu,
				tt, ioba, tces, npages);
		goto put_list_page_exit;
	}

	/* Emulated IO */
	for (i = 0; i < npages; ++i) {
		if (get_user(vcpu->arch.tce_tmp_hpas[i], tces + i)) {
			ret = H_PARAMETER;
			goto put_list_page_exit;
		}

		ret = kvmppc_tce_validate(vcpu->arch.tce_tmp_hpas[i]);
		if (ret)
			goto put_list_page_exit;
	}

	for (i = 0; i < npages; ++i)
		kvmppc_tce_put(tt, ioba + (i << IOMMU_PAGE_SHIFT),
				vcpu->arch.tce_tmp_hpas[i]);
put_list_page_exit:
	if (pg)
		put_page(pg);

	return ret;
}

long kvmppc_h_stuff_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *tt;
	long i, ret;

	tt = kvmppc_find_tce_table(vcpu->kvm, liobn);
	if (!tt)
		return H_TOO_HARD;

	if (tt->type == KVMPPC_TCET_IOMMU)
		return kvmppc_h_stuff_tce_iommu(vcpu, tt, liobn, ioba,
				tce_value, npages);

	/* Emulated IO */
	if ((ioba + (npages << IOMMU_PAGE_SHIFT)) > tt->window_size)
		return H_PARAMETER;

	ret = kvmppc_tce_validate(tce_value);
	if (ret || (tce_value & (TCE_PCI_WRITE | TCE_PCI_READ)))
		return H_PARAMETER;

	for (i = 0; i < npages; ++i, ioba += IOMMU_PAGE_SIZE)
		kvmppc_tce_put(tt, ioba, tce_value);

	return H_SUCCESS;
}
