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

#define TCES_PER_PAGE	(PAGE_SIZE / sizeof(u64))
#define ERROR_ADDR      (~(unsigned long)0x0)

/* Finds a TCE table descriptor by LIOBN.
 *
 * WARNING: This will be called in real or virtual mode on HV KVM and virtual
 *          mode on PR KVM
 */
struct kvmppc_spapr_tce_table *kvmppc_find_tce_table(struct kvm_vcpu *vcpu,
		unsigned long liobn)
{
	struct kvmppc_spapr_tce_table *tt;

	list_for_each_entry(tt, &vcpu->kvm->arch.spapr_tce_tables, list) {
		if (tt->liobn == liobn)
			return tt;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(kvmppc_find_tce_table);

/*
 * Validates TCE address.
 * At the moment only flags are validated.
 * As the host kernel does not access those addresses (just puts them
 * to the table and user space is supposed to process them), we can skip
 * checking other things (such as TCE is a guest RAM address or the page
 * was actually allocated).
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
long kvmppc_tce_validate(unsigned long tce)
{
	if (tce & ~(IOMMU_PAGE_MASK | TCE_PCI_WRITE | TCE_PCI_READ))
		return H_PARAMETER;

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_tce_validate);

/* Note on the use of page_address() in real mode,
 *
 * It is safe to use page_address() in real mode on ppc64 because
 * page_address() is always defined as lowmem_page_address()
 * which returns __va(PFN_PHYS(page_to_pfn(page))) which is arithmetial
 * operation and does not access page struct.
 *
 * Theoretically page_address() could be defined different
 * but either WANT_PAGE_VIRTUAL or HASHED_PAGE_VIRTUAL
 * should be enabled.
 * WANT_PAGE_VIRTUAL is never enabled on ppc32/ppc64,
 * HASHED_PAGE_VIRTUAL could be enabled for ppc32 only and only
 * if CONFIG_HIGHMEM is defined. As CONFIG_SPARSEMEM_VMEMMAP
 * is not expected to be enabled on ppc32, page_address()
 * is safe for ppc32 as well.
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
extern u64 *kvmppc_page_address(struct page *page)
{
#if defined(HASHED_PAGE_VIRTUAL) || defined(WANT_PAGE_VIRTUAL)
#error TODO: fix to avoid page_address() here
#endif
	return (u64 *) page_address(page);
}

/*
 * Handles TCE requests for emulated devices.
 * Puts guest TCE values to the table and expects user space to convert them.
 * Called in both real and virtual modes.
 * Cannot fail so kvmppc_tce_validate must be called before it.
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
void kvmppc_tce_put(struct kvmppc_spapr_tce_table *tt,
		unsigned long ioba, unsigned long tce)
{
	unsigned long idx = ioba >> SPAPR_TCE_SHIFT;
	struct page *page;
	u64 *tbl;

	page = tt->pages[idx / TCES_PER_PAGE];
	tbl = kvmppc_page_address(page);

	tbl[idx % TCES_PER_PAGE] = tce;
}
EXPORT_SYMBOL_GPL(kvmppc_tce_put);

#ifdef CONFIG_KVM_BOOK3S_64_HV
/*
 * Converts guest physical address to host physical address.
 * Tries to increase page counter via get_page_unless_zero() and
 * returns ERROR_ADDR if failed.
 */
static unsigned long kvmppc_rm_gpa_to_hpa_and_get(struct kvm_vcpu *vcpu,
		unsigned long gpa, struct page **pg)
{
	struct kvm_memory_slot *memslot;
	pte_t *ptep, pte;
	unsigned long hva, hpa = ERROR_ADDR;
	unsigned long gfn = gpa >> PAGE_SHIFT;
	unsigned shift = 0;

	memslot = search_memslots(kvm_memslots(vcpu->kvm), gfn);
	if (!memslot)
		return ERROR_ADDR;

	hva = __gfn_to_hva_memslot(memslot, gfn);

	ptep = find_linux_pte_or_hugepte(vcpu->arch.pgdir, hva, &shift);
	if (!ptep || !pte_present(*ptep))
		return ERROR_ADDR;
	pte = *ptep;

	if (!shift)
		shift = PAGE_SHIFT;

	/* Avoid handling anything potentially complicated in realmode */
	if (shift > PAGE_SHIFT)
		return ERROR_ADDR;

	if (((gpa & TCE_PCI_WRITE) || pte_write(pte)) && !pte_dirty(pte))
		return ERROR_ADDR;

	if (!pte_young(pte))
		return ERROR_ADDR;

	/* Increase page counter */
	*pg = realmode_pfn_to_page(pte_pfn(pte));
	if (!*pg || PageCompound(*pg) || !get_page_unless_zero(*pg))
		return ERROR_ADDR;

	hpa = (pte_pfn(pte) << PAGE_SHIFT) + (gpa & ((1 << shift) - 1));

	/* Page has gone since we got pte, safer to put the request to virt mode */
	if (unlikely(pte_val(pte) != pte_val(*ptep))) {
		hpa = ERROR_ADDR;
		/* Try drop the page, if failed, let virtmode do that */
		if (put_page_unless_one(*pg))
			*pg = NULL;
	}

	return hpa;
}

long kvmppc_rm_h_put_tce(struct kvm_vcpu *vcpu, unsigned long liobn,
		      unsigned long ioba, unsigned long tce)
{
	long ret;
	struct kvmppc_spapr_tce_table *tt;

	tt = kvmppc_find_tce_table(vcpu, liobn);
	if (!tt)
		return H_TOO_HARD;

	if (ioba >= tt->window_size)
		return H_PARAMETER;

	ret = kvmppc_tce_validate(tce);
	if (!ret)
		kvmppc_tce_put(tt, ioba, tce);

	return ret;
}

long kvmppc_rm_h_put_tce_indirect(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_list,	unsigned long npages)
{
	struct kvmppc_spapr_tce_table *tt;
	long i, ret = H_SUCCESS;
	unsigned long tces;
	struct page *pg = NULL;

	tt = kvmppc_find_tce_table(vcpu, liobn);
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

	tces = kvmppc_rm_gpa_to_hpa_and_get(vcpu, tce_list, &pg);
	if (tces == ERROR_ADDR) {
		ret = H_TOO_HARD;
		goto put_unlock_exit;
	}

	for (i = 0; i < npages; ++i) {
		ret = kvmppc_tce_validate(((unsigned long *)tces)[i]);
		if (ret)
			goto put_unlock_exit;
	}

	for (i = 0; i < npages; ++i)
		kvmppc_tce_put(tt, ioba + (i << IOMMU_PAGE_SHIFT),
				((unsigned long *)tces)[i]);

put_unlock_exit:
	if (!ret && pg && !put_page_unless_one(pg)) {
		vcpu->arch.tce_rm_fail = TCERM_PUTLIST;
		ret = H_TOO_HARD;
	}

	return ret;
}

long kvmppc_rm_h_stuff_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *tt;
	long i, ret;

	tt = kvmppc_find_tce_table(vcpu, liobn);
	if (!tt)
		return H_TOO_HARD;

	if ((ioba + (npages << IOMMU_PAGE_SHIFT)) > tt->window_size)
		return H_PARAMETER;

	ret = kvmppc_tce_validate(tce_value);
	if (ret || (tce_value & (TCE_PCI_WRITE | TCE_PCI_READ)))
		return H_PARAMETER;

	for (i = 0; i < npages; ++i, ioba += IOMMU_PAGE_SIZE)
		kvmppc_tce_put(tt, ioba, tce_value);

	return H_SUCCESS;
}
#endif /* CONFIG_KVM_BOOK3S_64_HV */
