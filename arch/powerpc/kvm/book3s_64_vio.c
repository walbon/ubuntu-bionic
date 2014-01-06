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

/*
 * API to support huge pages in real mode
 */
void kvmppc_iommu_hugepages_init(struct kvm_arch *ka)
{
	spin_lock_init(&ka->hugepages_write_lock);
	hash_init(ka->hugepages_hash_tab);
}
EXPORT_SYMBOL_GPL(kvmppc_iommu_hugepages_init);

void kvmppc_iommu_hugepages_cleanup(struct kvm_arch *ka)
{
	int bkt;
	struct kvmppc_spapr_iommu_hugepage *hp;
	struct hlist_node *tmp;

	spin_lock(&ka->hugepages_write_lock);
	hash_for_each_safe(ka->hugepages_hash_tab, bkt, tmp, hp, hash_node) {
		pr_debug("Release HP #%u gpa=%lx hpa=%lx size=%ld\n",
				bkt, hp->gpa, hp->hpa, hp->size);
		hlist_del_rcu(&hp->hash_node);

		put_page(hp->page);
		kfree(hp);
	}
	spin_unlock(&ka->hugepages_write_lock);
}
EXPORT_SYMBOL_GPL(kvmppc_iommu_hugepages_cleanup);

/* Returns true if a page with GPA is already in the hash table */
static bool kvmppc_iommu_hugepage_lookup_gpa(struct kvm_arch *ka,
		unsigned long gpa)
{
	struct kvmppc_spapr_iommu_hugepage *hp;
	const unsigned key = KVMPPC_SPAPR_HUGEPAGE_HASH(gpa);

	hash_for_each_possible_rcu(ka->hugepages_hash_tab, hp,
			hash_node, key) {
		if ((gpa < hp->gpa) || (gpa >= hp->gpa + hp->size))
			continue;

		return true;
	}

	return false;
}

/* Returns true if a page with GPA has been added to the hash table */
static bool kvmppc_iommu_hugepage_add(struct kvm_vcpu *vcpu,
		unsigned long hva, unsigned long gpa)
{
	struct kvm_arch *ka = &vcpu->kvm->arch;
	struct kvmppc_spapr_iommu_hugepage *hp;
	const unsigned key = KVMPPC_SPAPR_HUGEPAGE_HASH(gpa);
	pte_t *ptep;
	unsigned int shift = 0;
	static const int is_write = 1;

	ptep = find_linux_pte_or_hugepte(vcpu->arch.pgdir, hva, &shift);
	WARN_ON(!ptep);

	if (!ptep || (shift <= PAGE_SHIFT))
		return false;

	hp = kzalloc(sizeof(*hp), GFP_KERNEL);
	if (!hp)
		return false;

	hp->gpa = gpa & ~((1 << shift) - 1);
	hp->hpa = (pte_pfn(*ptep) << PAGE_SHIFT);
	hp->size = 1 << shift;

	if (get_user_pages_fast(hva & ~(hp->size - 1), 1,
			is_write, &hp->page) != 1) {
		kfree(hp);
		return false;
	}
	hash_add_rcu(ka->hugepages_hash_tab, &hp->hash_node, key);

	return true;
}

/*
 * Returns true if a page with GPA is in the hash table or
 * has just been added.
 */
static bool kvmppc_iommu_hugepage_try_add(struct kvm_vcpu *vcpu,
		unsigned long hva, unsigned long gpa)
{
	struct kvm_arch *ka = &vcpu->kvm->arch;
	bool ret;

	spin_lock(&ka->hugepages_write_lock);
	ret = kvmppc_iommu_hugepage_lookup_gpa(ka, gpa) ||
			kvmppc_iommu_hugepage_add(vcpu, hva, gpa);
	spin_unlock(&ka->hugepages_write_lock);

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
				stt, O_RDWR | O_CLOEXEC);

fail:
	if (stt) {
		for (i = 0; i < npages; i++)
			if (stt->pages[i])
				__free_page(stt->pages[i]);

		kfree(stt);
	}
	return ret;
}

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

	if (PageCompound(*pg)) {
		/*
		 * Check if this GPA is taken care of by the hash table.
		 * If this is the case, do not show the caller page struct
		 * address as huge pages will be released at KVM exit.
		 */
		if (kvmppc_iommu_hugepage_try_add(vcpu, hva, gpa)) {
			put_page(*pg);
			*pg = NULL;
		}
	}

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

	if (pg && !PageCompound(pg))
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
		if (pg && !PageCompound(pg))
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
EXPORT_SYMBOL_GPL(kvmppc_h_put_tce);

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
EXPORT_SYMBOL_GPL(kvmppc_h_put_tce_indirect);

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
EXPORT_SYMBOL_GPL(kvmppc_h_stuff_tce);
