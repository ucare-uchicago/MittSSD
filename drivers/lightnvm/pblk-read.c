/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-read.c - pblk's read path
 */

#include "pblk.h"

/*
 * There is no guarantee that the value read from cache has not been updated and
 * resides at another location in the cache. We guarantee though that if the
 * value is read from the cache, it belongs to the mapped lba. In order to
 * guarantee and order between writes and reads are ordered, a flush must be
 * issued.
 */
static int pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
				sector_t lba, struct ppa_addr ppa,
				int bio_iter)
{
	return pblk_rb_copy_to_bio(&pblk->rwb, bio, lba,
				nvm_addr_to_cacheline(ppa), bio_iter);
}

static int pblk_read_ppalist_rq(struct pblk *pblk, struct nvm_rq *rqd,
				unsigned long *read_bitmap)
{
	struct bio *bio = rqd->bio;
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	sector_t blba = pblk_get_lba(bio);
	int nr_secs = rqd->nr_ppas;
	int advanced_bio = 0;
	int i, j = 0;

	/* logic error: lba out-of-bounds */
	BUG_ON(!(blba >= 0 && blba + nr_secs < pblk->rl.nr_secs));

	pblk_lookup_l2p_seq(pblk, ppas, blba, nr_secs);

	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr *p = &ppas[i];
		sector_t lba = blba + i;

retry:
		if (ppa_empty(*p)) {
			WARN_ON(test_and_set_bit(i, read_bitmap));
			continue;
		}

		/* Try to read from write buffer. The address is later checked
		 * on the write buffer to prevent retrieving overwritten data.
		 */
		if (nvm_addr_in_cache(*p)) {
			if (!pblk_read_from_cache(pblk, bio, lba, *p, i)) {
				pblk_lookup_l2p_seq(pblk, p, lba, 1);
				goto retry;
			}
			WARN_ON(test_and_set_bit(i, read_bitmap));
			advanced_bio = 1;
		} else {
			/* Read from media non-cached sectors */
			rqd->ppa_list[j++] = *p;
		}

		if (advanced_bio)
			bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_secs, &pblk->inflight_reads);
#endif

	return NVM_IO_OK;
}

static int pblk_submit_read_io(struct pblk *pblk, struct nvm_rq *rqd)
{
	int err;

	rqd->flags = pblk_set_read_mode(pblk);

	err = pblk_submit_io(pblk, rqd);
	if (err)
		return NVM_IO_ERR;

	return NVM_IO_OK;
}

void pblk_end_io_read(struct nvm_rq *rqd)
{
    struct pblk *pblk = rqd->private;
    struct nvm_tgt_dev *dev = pblk->dev;
    struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
    struct bio *bio = rqd->bio;

    down_perlun_inf_rd(pblk, rqd);

#if 0
    /* Coperd: for reads hits the buffer, we don't have lun_bitmap for them */
    if (rqd->type == PBLK_IOTYPE_USER && r_ctx->lun_bitmap) {
        /* Coperd: update per-lun counter no matter whether it fails or not */
        while ((bit = find_next_bit(lun_bitmap, nr_luns, bit + 1)) < nr_luns) {
            tlun = &pblk->luns[bit];
            atomic_dec(&tlun->inf_rd);
            /* Coperd: TOFIX, only work for one LUN now */
            if (rqd->nr_ppas <= geo->sec_per_pg)
                atomic_dec(&tlun->inf_rd_pgs);
            else {
                int nr_ef_pgs = rqd->nr_ppas / geo->sec_per_pg + 1;
                atomic_sub(nr_ef_pgs, &tlun->inf_rd_pgs);
            }
        }
        kfree(r_ctx->lun_bitmap);

    }
#endif

    if (rqd->error)
        pblk_log_read_err(pblk, rqd);
#ifdef CONFIG_NVM_DEBUG
    else
        BUG_ON(bio->bi_error);
#endif

    if (rqd->nr_ppas > 1)
        nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

    bio_put(bio);
    /* Coperd: for partial reads, no r_ctx->orig_bio set, only for full reads */
    if (r_ctx->orig_bio) {
#ifdef CONFIG_NVM_DEBUG
        WARN_ON(r_ctx->orig_bio->bi_error);
#endif
        bio_endio(r_ctx->orig_bio);
        bio_put(r_ctx->orig_bio);
    }

#ifdef CONFIG_NVM_DEBUG
    atomic_add(rqd->nr_ppas, &pblk->sync_reads);
    atomic_sub(rqd->nr_ppas, &pblk->inflight_reads);
#endif

    pblk_free_rqd(pblk, rqd, READ);
}

static int pblk_fill_partial_read_bio(struct pblk *pblk, struct nvm_rq *rqd,
				      unsigned int bio_init_idx,
				      unsigned long *read_bitmap)
{
	struct bio *new_bio, *bio = rqd->bio;
    struct nvm_tgt_dev *dev = pblk->dev;
	struct bio_vec src_bv, dst_bv;
	void *ppa_ptr = NULL;
	void *src_p, *dst_p;
	dma_addr_t dma_ppa_list = 0;
	int nr_secs = rqd->nr_ppas;
	int nr_holes = nr_secs - bitmap_weight(read_bitmap, nr_secs);
	int i, ret, hole;
    struct ppa_addr *ppa_list;
    struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
    u64 lun_id;
	DECLARE_COMPLETION_ONSTACK(wait);

	new_bio = bio_alloc(GFP_KERNEL, nr_holes);
	if (!new_bio) {
		pr_err("pblk: could not alloc read bio\n");
		ret = NVM_IO_ERR;
        goto free_rqd;
	}

	if (pblk_bio_add_pages(pblk, new_bio, GFP_KERNEL, nr_holes)) {
        ret = NVM_IO_ERR;
		goto free_new_bio;
    }

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
        ret = NVM_IO_ERR;
		goto free_bio_add_pages;
	}

	new_bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);
	new_bio->bi_private = &wait;
	new_bio->bi_end_io = pblk_end_bio_sync;

    /* Coperd: double check that new_bio inherits hflag from the original one */
    new_bio->hflag = bio->hflag;
	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;
	rqd->end_io = NULL;

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		ppa_ptr = rqd->ppa_list;
		dma_ppa_list = rqd->dma_ppa_list;
		rqd->ppa_addr = rqd->ppa_list[0];
	}

    /* Coperd: create per-rq target lun bitmap */
    ppa_list = (nr_secs > 1) ? rqd->ppa_list : &rqd->ppa_addr;
    r_ctx->flags = PBLK_IOTYPE_USER;
    r_ctx->lun_bitmap = kzalloc(pblk->lm.lun_bitmap_len, GFP_KERNEL);
    if (!r_ctx->lun_bitmap) {
        pr_err("pblk: out of memory to create request lun_bitmap\n");
        ret = NVM_IO_ERR;
        goto free_bio_add_pages;
    }
    for (i = 0; i < rqd->nr_ppas; i++) {
        lun_id = pblk_ppa_to_lun(pblk, ppa_list[i]);
        set_bit(lun_id, r_ctx->lun_bitmap);
    }

	ret = pblk_submit_read_io(pblk, rqd);
	if (ret) {
		//pr_err("pblk: read IO submission failed\n");
		goto free_lun_bitmap;
	}

	wait_for_completion_io(&wait);

	if (rqd->error) {
		inc_stat(pblk, &pblk->read_failed, 0);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif

        /* Coperd: if read fails, shouldn't we handle error here and return ? */
	}

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		rqd->ppa_list = ppa_ptr;
		rqd->dma_ppa_list = dma_ppa_list;
	}

	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_secs);
	do {
		src_bv = new_bio->bi_io_vec[i++];
		dst_bv = bio->bi_io_vec[bio_init_idx + hole];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

		mempool_free(src_bv.bv_page, pblk->page_pool);

		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_secs);

	bio_put(new_bio);

	/* Complete the original bio and associated request */
	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;
	rqd->private = pblk;

	bio_endio(bio);
	pblk_end_io_read(rqd);
	return NVM_IO_OK;

free_lun_bitmap:
    kfree(r_ctx->lun_bitmap);

free_bio_add_pages:
	/* Free allocated pages in new bio */
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);

free_new_bio:
    bio_put(new_bio);
    // Coperd: do we need to de-allocate the new bio here ???
	rqd->private = pblk;

free_rqd:
    if (rqd->nr_ppas > 1)
        nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);
    pblk_free_rqd(pblk, rqd, READ);

	return ret;
}

static int pblk_read_rq(struct pblk *pblk, struct nvm_rq *rqd,
			unsigned long *read_bitmap)
{
	struct bio *bio = rqd->bio;
	struct ppa_addr ppa;
	sector_t lba = pblk_get_lba(bio);

	/* logic error: lba out-of-bounds */
	BUG_ON(!(lba >= 0 && lba < pblk->rl.nr_secs));

	pblk_lookup_l2p_seq(pblk, &ppa, lba, 1);

retry:
	if (ppa_empty(ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		return NVM_IO_DONE;
	}

	/* Try to read from write buffer. The address is later checked on the
	 * write buffer to prevent retrieving overwritten data.
	 */
	if (nvm_addr_in_cache(ppa)) {
		if (!pblk_read_from_cache(pblk, bio, lba, ppa, 0)) {
			pblk_lookup_l2p_seq(pblk, &ppa, lba, 1);
			goto retry;
		}
		WARN_ON(test_and_set_bit(0, read_bitmap));
	} else {
		rqd->ppa_addr = ppa;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_reads);
#endif
	return NVM_IO_OK;
}

#if 0
static int nr_ppr = 0, nr_mpr = 0;
#endif

int pblk_submit_read(struct pblk *pblk, struct bio *bio)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	int nr_secs = pblk_get_secs(bio);
	struct nvm_rq *rqd;
	unsigned long read_bitmap; /* Max 64 ppas per request */
    struct pblk_r_ctx *r_ctx; 
	unsigned int bio_init_idx;
	int ret = NVM_IO_ERR;

#if 0
    if (bio->hflag)
        nr_mpr++;
    else
        nr_ppr++;

    printk("Coperd,nr_ppr=%d,nr_mpr=%d\n", nr_ppr, nr_mpr);
#endif

	if (nr_secs > PBLK_MAX_REQ_ADDRS)
		return NVM_IO_ERR;

	bitmap_zero(&read_bitmap, nr_secs);

	rqd = pblk_alloc_rqd(pblk, READ);
	if (IS_ERR(rqd)) {
		pr_err_ratelimited("pblk: not able to alloc rqd");
		return NVM_IO_ERR;
	}

    /* Coperd: add a quick way for passing hflag from sysfs */
    if (pblk->tos_def_hflag)
        bio->hflag = pblk->tos_def_hflag;

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;
	rqd->private = pblk;
	rqd->end_io = pblk_end_io_read;
    rqd->type = PBLK_IOTYPE_USER;

	/* Save the index for this bio's start. This is needed in case
	 * we need to fill a partial read.
	 */
	bio_init_idx = pblk_get_bi_idx(bio);

	if (nr_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
						&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			goto fail_rqd_free;
		}

		pblk_read_ppalist_rq(pblk, rqd, &read_bitmap);
	} else
		pblk_read_rq(pblk, rqd, &read_bitmap);

    /* Coperd: 1=> whole read hits cache */
	bio_get(bio); /* Coperd: why do we do bio_get here ??? */
	if (bitmap_full(&read_bitmap, nr_secs)) {
        atomic_inc(&pblk->nr_cc_rds);
		bio_endio(bio);
		pblk_end_io_read(rqd);
		return NVM_IO_OK;
	}

    r_ctx = nvm_rq_to_pdu(rqd);

	/* Coperd: 2=> All sectors are to be read from the device */

	if (bitmap_empty(&read_bitmap, rqd->nr_ppas)) {
        int i;
        struct ppa_addr *ppa_list = (nr_secs > 1) ? rqd->ppa_list : &rqd->ppa_addr;
		struct bio *int_bio = NULL;
        u64 lun_id;

		/* Clone read bio to deal with read errors internally */
		int_bio = bio_clone_bioset(bio, GFP_KERNEL, fs_bio_set);
		if (!int_bio) {
			pr_err("pblk: could not clone read bio\n");
			ret = NVM_IO_ERR;
            goto free_rqd_dma;
		}

        /* Coperd: double check that int_bio inherits hflag from bio */
        int_bio->hflag = bio->hflag;
		rqd->bio = int_bio;
        r_ctx->flags = PBLK_IOTYPE_USER;
		r_ctx->orig_bio = bio;
        r_ctx->lun_bitmap = kzalloc(pblk->lm.lun_bitmap_len, GFP_KERNEL);
        if (!r_ctx->lun_bitmap) {
            pr_err("pblk: out of memory to create request lun_bitmap\n");
            ret = NVM_IO_ERR;
            goto free_int_bio;
        }
        for (i = 0; i < rqd->nr_ppas; i++) {
            lun_id = pblk_ppa_to_lun(pblk, ppa_list[i]);
            set_bit(lun_id, r_ctx->lun_bitmap);
        }

		ret = pblk_submit_read_io(pblk, rqd);
		if (ret) {
			//pr_err("pblk: read IO submission failed\n");
            goto free_lun_bitmap;
		}

		return NVM_IO_OK;
	}

	/* 
     * Coperd: 3=> The read bio request could be partially filled by the write 
     * buffer, but there are some holes that need to be read from the drive.
	 */
	ret = pblk_fill_partial_read_bio(pblk, rqd, bio_init_idx, &read_bitmap);
	if (ret) {
		pr_err("pblk: failed to perform partial read\n");
        return ret;
	}

	return NVM_IO_OK;

free_lun_bitmap:
    kfree(r_ctx->lun_bitmap);

free_int_bio:
    bio_put(rqd->bio); /* Coperd: free int_bio here */

free_rqd_dma:
    if (rqd->nr_ppas > 1)
        nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

fail_rqd_free:
	pblk_free_rqd(pblk, rqd, READ);

	return ret;
}

static int read_ppalist_rq_gc(struct pblk *pblk, struct nvm_rq *rqd,
			      struct pblk_line *line, u64 *lba_list,
			      unsigned int nr_secs)
{
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	int valid_secs = 0;
	int i;

	pblk_lookup_l2p_rand(pblk, ppas, lba_list, nr_secs);

	for (i = 0; i < nr_secs; i++) {
		/* Ignore updated values until the moment */
		if (nvm_addr_in_cache(ppas[i]) || ppas[i].g.blk != line->id ||
							ppa_empty(ppas[i])) {
			lba_list[i] = ADDR_EMPTY;
			continue;
		}

		rqd->ppa_list[valid_secs++] = ppas[i];
	}

#ifdef CONFIG_NVM_DEBUG
		atomic_add(valid_secs, &pblk->inflight_reads);
#endif
	return valid_secs;
}

static int read_rq_gc(struct pblk *pblk, struct nvm_rq *rqd,
		      struct pblk_line *line, sector_t lba)
{
	struct ppa_addr ppa;
	int valid_secs = 0;

	if (lba == ADDR_EMPTY)
		goto out;

	/* logic error: lba out-of-bounds */
	BUG_ON(!(lba >= 0 && lba < pblk->rl.nr_secs));

	spin_lock(&pblk->trans_lock);
	ppa = pblk->trans_map[lba];
	spin_unlock(&pblk->trans_lock);

	/* Ignore updated values until the moment */
	if (nvm_addr_in_cache(ppa) || ppa.g.blk != line->id || ppa_empty(ppa))
		goto out;

	rqd->ppa_addr = ppa;
	valid_secs = 1;

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_reads);
#endif
	return NVM_IO_OK;
out:
	return valid_secs;
}

int pblk_submit_read_gc(struct pblk *pblk, u64 *lba_list, void *data,
			unsigned int nr_secs, unsigned int *secs_to_gc,
			struct pblk_line *line)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct request_queue *q = dev->q;
	struct bio *bio;
	struct nvm_rq rqd;
	int ret, data_len;
	DECLARE_COMPLETION_ONSTACK(wait);

	memset(&rqd, 0, sizeof(struct nvm_rq));

	if (nr_secs > 1) {
		rqd.ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
						  &rqd.dma_ppa_list);
		if (!rqd.ppa_list)
			return NVM_IO_ERR;

		*secs_to_gc = read_ppalist_rq_gc(pblk, &rqd, line, lba_list,
								nr_secs);
		if (*secs_to_gc == 1) {
			struct ppa_addr ppa;

			ppa = rqd.ppa_list[0];
			nvm_dev_dma_free(dev->parent, rqd.ppa_list,
							rqd.dma_ppa_list);
			rqd.ppa_addr = ppa;
		}
	} else {
		*secs_to_gc = read_rq_gc(pblk, &rqd, line, lba_list[0]);
	}

	if (!(*secs_to_gc))
		goto out;

	data_len = (*secs_to_gc) * geo->sec_size;
	bio = bio_map_kern(q, data, data_len, GFP_KERNEL);
	if (!bio) {
		pr_err("pblk: could not allocate GC bio\n");
		goto err_free_dma;
	}

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_bio_sync;

	rqd.opcode = NVM_OP_PREAD;
	rqd.nr_ppas = *secs_to_gc;
	rqd.bio = bio;
    rqd.type = PBLK_IOTYPE_GC;

	ret = pblk_submit_read_io(pblk, &rqd);
	if (ret) {
		bio_endio(bio);
		pr_err("pblk: GC read request failed\n");
		goto err_free_bio;
	}
	wait_for_completion_io(&wait);

    down_perlun_inf_rd(pblk, &rqd);

	if (rqd.error) {
		inc_stat(pblk, &pblk->read_failed_gc, 0);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, &rqd, rqd.error);
#endif
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(*secs_to_gc, &pblk->sync_reads);
	atomic_sub(*secs_to_gc, &pblk->inflight_reads);
#endif

	bio_put(bio);
out:
	if (rqd.nr_ppas > 1)
		nvm_dev_dma_free(dev->parent, rqd.ppa_list, rqd.dma_ppa_list);
	return NVM_IO_OK;

err_free_bio:
	bio_put(bio);
err_free_dma:
	if (rqd.nr_ppas > 1)
		nvm_dev_dma_free(dev->parent, rqd.ppa_list, rqd.dma_ppa_list);
	return NVM_IO_ERR;
}
