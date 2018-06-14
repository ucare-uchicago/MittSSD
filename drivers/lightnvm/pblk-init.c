/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
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
 * Implementation of a physical block-device target for Open-channel SSDs.
 *
 * pblk-init.c - pblk's initialization. Derived from rrpc.c
 */

#include "pblk.h"

struct pinfo *rqst;
volatile int rq_idx;
DEFINE_SPINLOCK(mt_lock);

static struct kmem_cache *pblk_blk_ws_cache, *pblk_rec_cache, *pblk_r_rq_cache,
					*pblk_w_rq_cache, *pblk_line_meta_cache;
static DECLARE_RWSEM(pblk_lock);

static const struct block_device_operations pblk_fops = {
	.owner		= THIS_MODULE,
};

static int pblk_rw_io(struct request_queue *q, struct pblk *pblk,
			  struct bio *bio)
{
	int ret;

	/* Read requests must be <= 256kb due to NVMe's 64 bit completion bitmap
	 * constraint. Writes can be of arbitrary size.
	 */
	if (bio_data_dir(bio) == READ) {
		blk_queue_split(q, &bio, q->bio_split);
		ret = pblk_submit_read(pblk, bio);
		if (ret == NVM_IO_DONE && bio_flagged(bio, BIO_CLONED))
			bio_put(bio);

		return ret;
	}

	/* Prevent deadlock in the case of a modest LUN configuration and large
	 * user I/Os. Unless stalled, the rate limiter leaves at least 256KB
	 * available for user I/O.
	 */
	if (unlikely(pblk_get_secs(bio) >= pblk_rl_sysfs_rate_show(&pblk->rl)))
		blk_queue_split(q, &bio, q->bio_split);

	return pblk_write_to_cache(pblk, bio, PBLK_IOTYPE_USER);
}

static blk_qc_t pblk_make_rq(struct request_queue *q, struct bio *bio)
{
	struct pblk *pblk = q->queuedata;

	if (bio_op(bio) == REQ_OP_DISCARD) {
		pblk_discard(pblk, bio);
		if (!(bio->bi_opf & REQ_PREFLUSH)) {
			bio_endio(bio);
			return BLK_QC_T_NONE;
		}
	}

	switch (pblk_rw_io(q, pblk, bio)) {
	case NVM_IO_ERR:
		bio_io_error(bio);
		break;
	case NVM_IO_DONE:
		bio_endio(bio);
		break;
	}

	return BLK_QC_T_NONE;
}

static void pblk_l2p_free(struct pblk *pblk)
{
	vfree(pblk->trans_map);
}

static int pblk_l2p_init(struct pblk *pblk)
{
	sector_t i;

	pblk->trans_map = vmalloc(sizeof(struct ppa_addr) * pblk->rl.nr_secs);
	if (!pblk->trans_map)
		return -ENOMEM;

	for (i = 0; i < pblk->rl.nr_secs; i++)
		ppa_set_empty(&pblk->trans_map[i]);

	return 0;
}

int lun_wr_lat_tbl_init(struct pblk *pblk, struct pblk_lun *tlun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
    int nr_pgs = geo->blks_per_lun * geo->pgs_per_blk;
    int i;
    pr_debug("Coperd, allocating latency table [%d] entries!\n", nr_pgs);
    tlun->wr_lat_tbl = vmalloc(sizeof(u32) * nr_pgs);
    if (!tlun->wr_lat_tbl)
        return -ENOMEM;

    for (i = 0; i < nr_pgs; i++)
        tlun->wr_lat_tbl[i] = 0;

    return 0;
}

static void lun_wr_lat_tbl_free(struct pblk_lun *tlun)
{
    vfree(tlun->wr_lat_tbl);
}

static void pblk_rwb_free(struct pblk *pblk)
{
	pblk_rb_data_free(&pblk->rwb);
	vfree(pblk_rb_entries_ref(&pblk->rwb));
	pblk_rl_free(&pblk->rl);
}

static int pblk_rwb_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_rb_entry *entries;
	int pgs_in_rb;
	unsigned long nr_entries;
	unsigned int power_size, power_seg_sz;

	pgs_in_rb = NVM_MEM_PAGE_WRITE * geo->sec_per_pg *
				geo->nr_planes * geo->nr_luns;
	nr_entries = pblk_rb_calculate_size(pblk->pgs_in_buffer);

	entries = vzalloc(nr_entries * sizeof(struct pblk_rb_entry));
	if (!entries)
		return -ENOMEM;

	power_size = get_count_order(nr_entries);
	power_seg_sz = get_count_order(geo->sec_size);

	return pblk_rb_init(&pblk->rwb, entries, power_size, power_seg_sz);
}

/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int pblk_set_ppaf(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct nvm_addr_format ppaf = geo->ppaf;
	int power_len;

	/* Re-calculate channel and lun format to adapt to configuration */
	power_len = get_count_order(geo->nr_chnls);
	if (1 << power_len != geo->nr_chnls) {
		pr_err("pblk: supports only power-of-two channel config.\n");
		return -EINVAL;
	}
	ppaf.ch_len = power_len;

	power_len = get_count_order(geo->luns_per_chnl);
	if (1 << power_len != geo->luns_per_chnl) {
		pr_err("pblk: supports only power-of-two LUN config.\n");
		return -EINVAL;
	}
	ppaf.lun_len = power_len;

	pblk->ppaf.sec_offset = 0;
	pblk->ppaf.pln_offset = ppaf.sect_len;
	pblk->ppaf.ch_offset = pblk->ppaf.pln_offset + ppaf.pln_len;
	pblk->ppaf.lun_offset = pblk->ppaf.ch_offset + ppaf.ch_len;
	pblk->ppaf.pg_offset = pblk->ppaf.lun_offset + ppaf.lun_len;
	pblk->ppaf.blk_offset = pblk->ppaf.pg_offset + ppaf.pg_len;
	pblk->ppaf.sec_mask = (1ULL << ppaf.sect_len) - 1;
	pblk->ppaf.pln_mask = ((1ULL << ppaf.pln_len) - 1) <<
							pblk->ppaf.pln_offset;
	pblk->ppaf.ch_mask = ((1ULL << ppaf.ch_len) - 1) <<
							pblk->ppaf.ch_offset;
	pblk->ppaf.lun_mask = ((1ULL << ppaf.lun_len) - 1) <<
							pblk->ppaf.lun_offset;
	pblk->ppaf.pg_mask = ((1ULL << ppaf.pg_len) - 1) <<
							pblk->ppaf.pg_offset;
	pblk->ppaf.blk_mask = ((1ULL << ppaf.blk_len) - 1) <<
							pblk->ppaf.blk_offset;

	return 0;
}

static int pblk_init_global_caches(struct pblk *pblk)
{
	down_write(&pblk_lock);
	pblk_blk_ws_cache = kmem_cache_create("pblk_blk_ws",
				sizeof(struct pblk_line_ws), 0, 0, NULL);
	if (!pblk_blk_ws_cache) {
		up_write(&pblk_lock);
		return -ENOMEM;
	}

	pblk_rec_cache = kmem_cache_create("pblk_rec",
				sizeof(struct pblk_rec_ctx), 0, 0, NULL);
	if (!pblk_rec_cache) {
		kmem_cache_destroy(pblk_blk_ws_cache);
		up_write(&pblk_lock);
		return -ENOMEM;
	}

	pblk_r_rq_cache = kmem_cache_create("pblk_r_rq", pblk_r_rq_size,
				0, 0, NULL);
	if (!pblk_r_rq_cache) {
		kmem_cache_destroy(pblk_blk_ws_cache);
		kmem_cache_destroy(pblk_rec_cache);
		up_write(&pblk_lock);
		return -ENOMEM;
	}

	pblk_w_rq_cache = kmem_cache_create("pblk_w_rq", pblk_w_rq_size,
				0, 0, NULL);
	if (!pblk_w_rq_cache) {
		kmem_cache_destroy(pblk_blk_ws_cache);
		kmem_cache_destroy(pblk_rec_cache);
		kmem_cache_destroy(pblk_r_rq_cache);
		up_write(&pblk_lock);
		return -ENOMEM;
	}

	pblk_line_meta_cache = kmem_cache_create("pblk_line_m",
				pblk->lm.sec_bitmap_len, 0, 0, NULL);
	if (!pblk_line_meta_cache) {
		kmem_cache_destroy(pblk_blk_ws_cache);
		kmem_cache_destroy(pblk_rec_cache);
		kmem_cache_destroy(pblk_r_rq_cache);
		kmem_cache_destroy(pblk_w_rq_cache);
		up_write(&pblk_lock);
		return -ENOMEM;
	}
	up_write(&pblk_lock);

	return 0;
}

static int pblk_core_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int max_write_ppas;
	int mod;

	pblk->min_write_pgs = geo->sec_per_pl * (geo->sec_size / PAGE_SIZE);
	max_write_ppas = pblk->min_write_pgs * geo->nr_luns;
	pblk->max_write_pgs = (max_write_ppas < nvm_max_phys_sects(dev)) ?
				max_write_ppas : nvm_max_phys_sects(dev);
	pblk->pgs_in_buffer = NVM_MEM_PAGE_WRITE * geo->sec_per_pg *
						geo->nr_planes * geo->nr_luns;

	if (pblk->max_write_pgs > PBLK_MAX_REQ_ADDRS) {
		pr_err("pblk: cannot support device max_phys_sect\n");
		return -EINVAL;
	}

	div_u64_rem(geo->sec_per_blk, pblk->min_write_pgs, &mod);
	if (mod) {
		pr_err("pblk: bad configuration of sectors/pages\n");
		return -EINVAL;
	}

	if (pblk_init_global_caches(pblk))
		return -ENOMEM;

	pblk->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!pblk->page_pool)
		return -ENOMEM;

	pblk->line_ws_pool = mempool_create_slab_pool(geo->nr_luns,
							pblk_blk_ws_cache);
	if (!pblk->line_ws_pool)
		goto free_page_pool;

	pblk->rec_pool = mempool_create_slab_pool(geo->nr_luns, pblk_rec_cache);
	if (!pblk->rec_pool)
		goto free_blk_ws_pool;

	pblk->r_rq_pool = mempool_create_slab_pool(64, pblk_r_rq_cache);
	if (!pblk->r_rq_pool)
		goto free_rec_pool;

	pblk->w_rq_pool = mempool_create_slab_pool(64, pblk_w_rq_cache);
	if (!pblk->w_rq_pool)
		goto free_r_rq_pool;

	pblk->line_meta_pool =
			mempool_create_slab_pool(16, pblk_line_meta_cache);
	if (!pblk->line_meta_pool)
		goto free_w_rq_pool;

	pblk->kw_wq = alloc_workqueue("pblk-writer",
					WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!pblk->kw_wq)
		goto free_line_meta_pool;

	if (pblk_set_ppaf(pblk))
		goto free_kw_wq;

	if (pblk_rwb_init(pblk))
		goto free_kw_wq;

	INIT_LIST_HEAD(&pblk->compl_list);
	return 0;

free_kw_wq:
	destroy_workqueue(pblk->kw_wq);
free_line_meta_pool:
	mempool_destroy(pblk->line_meta_pool);
free_w_rq_pool:
	mempool_destroy(pblk->w_rq_pool);
free_r_rq_pool:
	mempool_destroy(pblk->r_rq_pool);
free_rec_pool:
	mempool_destroy(pblk->rec_pool);
free_blk_ws_pool:
	mempool_destroy(pblk->line_ws_pool);
free_page_pool:
	mempool_destroy(pblk->page_pool);
	return -ENOMEM;
}

static void pblk_core_free(struct pblk *pblk)
{
	if (pblk->kw_wq)
		destroy_workqueue(pblk->kw_wq);

	pblk_rwb_free(pblk);

	mempool_destroy(pblk->page_pool);
	mempool_destroy(pblk->line_ws_pool);
	mempool_destroy(pblk->rec_pool);
	mempool_destroy(pblk->r_rq_pool);
	mempool_destroy(pblk->w_rq_pool);
	mempool_destroy(pblk->line_meta_pool);

	kmem_cache_destroy(pblk_blk_ws_cache);
	kmem_cache_destroy(pblk_rec_cache);
	kmem_cache_destroy(pblk_r_rq_cache);
	kmem_cache_destroy(pblk_w_rq_cache);
	kmem_cache_destroy(pblk_line_meta_cache);
}

static void pblk_luns_free(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *tlun;
    int nr_luns = geo->nr_luns;
    int i;

    for (i = 0; i < nr_luns; i++) {
        tlun = &pblk->luns[i];
        lun_wr_lat_tbl_free(tlun);
    }

	kfree(pblk->luns);
}

static void pblk_lines_free(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;
	int i;

	spin_lock(&l_mg->free_lock);
	for (i = 0; i < l_mg->nr_lines; i++) {
		line = &pblk->lines[i];

		pblk_line_free(pblk, line);
		kfree(line->blk_bitmap);
		kfree(line->erase_bitmap);
	}
	spin_unlock(&l_mg->free_lock);
}

static void pblk_line_meta_free(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	int i;

	kfree(l_mg->bb_template);
	kfree(l_mg->bb_aux);

	pblk_mfree(l_mg->gc_meta.meta, l_mg->emeta_alloc_type);
	for (i = 0; i < PBLK_DATA_LINES; i++) {
		pblk_mfree(l_mg->sline_meta[i].meta, l_mg->smeta_alloc_type);
		pblk_mfree(l_mg->eline_meta[i].meta, l_mg->emeta_alloc_type);
	}

	kfree(pblk->lines);
}

static int pblk_bb_discovery(struct nvm_tgt_dev *dev, struct pblk_lun *rlun)
{
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr ppa;
	u8 *blks;
	int nr_blks, ret;

	nr_blks = geo->blks_per_lun * geo->plane_mode;
	blks = kmalloc(nr_blks, GFP_KERNEL);
	if (!blks)
		return -ENOMEM;

	ppa.ppa = 0;
	ppa.g.ch = rlun->bppa.g.ch;
	ppa.g.lun = rlun->bppa.g.lun;

	ret = nvm_get_tgt_bb_tbl(dev, ppa, blks);
	if (ret)
		goto out;

	nr_blks = nvm_bb_tbl_fold(dev->parent, blks, nr_blks);
	if (nr_blks < 0) {
		kfree(blks);
		ret = nr_blks;
	}

	rlun->bb_list = blks;

out:
	return ret;
}

static int pblk_bb_line(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_lun *rlun;
	int bb_cnt = 0;
	int i;

	line->blk_bitmap = kzalloc(lm->blk_bitmap_len, GFP_KERNEL);
	if (!line->blk_bitmap)
		return -ENOMEM;

	line->erase_bitmap = kzalloc(lm->blk_bitmap_len, GFP_KERNEL);
	if (!line->erase_bitmap) {
		kfree(line->blk_bitmap);
		return -ENOMEM;
	}

	for (i = 0; i < lm->blk_per_line; i++) {
		rlun = &pblk->luns[i];
		if (rlun->bb_list[line->id] == NVM_BLK_T_FREE)
			continue;

		set_bit(i, line->blk_bitmap);
		bb_cnt++;
	}

	return bb_cnt;
}

/* Coperd: Hardcodeded L95B lower/upper page program latency data */
void tos_wr_lat_tbl_init(struct pblk *pblk)
{
    int i;
    int lowp[] = {0, 1, 2, 3, 4, 5, 7, 8, 502, 503, 506, 507, 509, 510};
    int upp[] = {6, 9, 504, 505, 508, 511};
    int lpflag = 0;

    for (i = 0; i < sizeof(lowp)/sizeof(lowp[0]); i++)
        pblk->wr_lat_tbl[lowp[i]] = 0;

    for (i = 0; i < sizeof(upp)/sizeof(upp[0]); i++)
        pblk->wr_lat_tbl[upp[i]] = 1;

    for (i = 10; i <= 500; i += 2) {
        pblk->wr_lat_tbl[i] = pblk->wr_lat_tbl[i+1] = lpflag;
        lpflag = !lpflag;
    }
}

static int pblk_luns_init(struct pblk *pblk, struct ppa_addr *luns)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	int i, j, ret;

	/* TODO: Implement unbalanced LUN support */
	if (geo->luns_per_chnl < 0) {
		pr_err("pblk: unbalanced LUN config.\n");
		return -EINVAL;
	}

	pblk->luns = kcalloc(geo->nr_luns, sizeof(struct pblk_lun), GFP_KERNEL);
	if (!pblk->luns)
		return -ENOMEM;

    pblk->tos_debug = 0;
    pblk->tos_debug_freq = 1000;
    pblk->tos_switch = 0;
    pblk->tos_gc_switch = 1;
    pblk->tos_tgt_lat = 1500;
    pblk->tos_def_hflag = 0;

    /* Coperd: initial coefficients of inf-counters for latency prediction */
    pblk->coef_rd = 100;
    pblk->coef_lp_wr = 900;
    pblk->coef_up_wr = 2400;
    pblk->coef_er = 6000;
    pblk->coef_cc = 15;
    /* Coperd: init wr_lat_table for all blocks */
    tos_wr_lat_tbl_init(pblk);

    pblk->tos_nr_wr_sem_max = 1;
    pblk->tos_pr_lat = 0;

	for (i = 0; i < geo->nr_luns; i++) {
		/* Stripe across channels */
		int ch = i % geo->nr_chnls;
		int lun_raw = i / geo->nr_chnls;
		int lunid = lun_raw + ch * geo->luns_per_chnl;

		rlun = &pblk->luns[i];
		rlun->bppa = luns[lunid];
        spin_lock_init(&rlun->lock);
        rlun->next_avail_time = 0;

		sema_init(&rlun->wr_sem, pblk->tos_nr_wr_sem_max);
        atomic_set(&rlun->inf_rd, 0);
        atomic_set(&rlun->inf_rd_pgs, 0);
        atomic_set(&rlun->inf_wr, 0);
        atomic_set(&rlun->inf_er, 0);
        for (j = 0; j < WR_SEM_MAX + 1; j++)
            atomic_set(&rlun->inf_wr_freq[j], 0);
        atomic_set(&rlun->nr_tt_rds, 0);
        atomic_set(&rlun->nr_tt_wrs, 0);
        atomic_set(&rlun->nr_tt_ers, 0);
        rlun->last_wr_stime = 0;
        rlun->last_wr_addr.ppa = ADDR_EMPTY;
        rlun->last_wr_lat_us = 0;
        rlun->last_er_stime = 0;
        rlun->last_er_lat_us = 0;
        rlun->last_rd_stime = 0;
        rlun->last_rd_lat_us = 0;
        INIT_LIST_HEAD(&rlun->inf_rqds);
#if 0
        ret = lun_wr_lat_tbl_init(pblk, rlun);
        if (ret) {
            pr_err("pblk: could not initialize perlun write latency table\n");
            return -ENOMEM;
        }
#endif
		ret = pblk_bb_discovery(dev, rlun);
		if (ret) {
			while (--i >= 0)
				kfree(pblk->luns[i].bb_list);
			return ret;
		}
	}

	return 0;
}

static int pblk_lines_configure(struct pblk *pblk)
{
	struct pblk_line *line;
	int ret = 0;

	/* Configure next line for user data */
	line = pblk_line_get_first_data(pblk);
	if (!line) {
		pr_err("pblk: line list corrupted\n");
		ret = -EFAULT;
		goto out;
	}

	line = pblk_line_get_next_data(pblk);
	if (!line) {
		struct pblk_line_mgmt *l_mg = &pblk->l_mg;

		kref_put(&l_mg->data_line->ref, pblk_line_put);
		pr_debug("pblk: starting instance with single data line\n");
		goto out;
	}

out:
	return ret;
}

/* See comment over struct line_emeta definition */
static unsigned int calc_emeta_len(struct pblk *pblk, struct pblk_line_meta *lm)
{
	return (sizeof(struct line_emeta) +
			((lm->sec_per_line - lm->emeta_sec) * sizeof(u64)) +
			(pblk->l_mg.nr_lines * sizeof(u32)) +
			lm->blk_bitmap_len);
}

/* TODO: Fit lba list in u32 when possible to use less pages */
static int pblk_lines_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *line;
	unsigned int smeta_len, emeta_len;
	int bb_distance;
	int nr_bad_blks;
	int i;
	int ret = 0;

	lm->sec_per_line = geo->sec_per_blk * geo->nr_luns;
	lm->blk_per_line = geo->nr_luns;
	lm->blk_bitmap_len = BITS_TO_LONGS(geo->nr_luns) * sizeof(long);
	lm->sec_bitmap_len = BITS_TO_LONGS(lm->sec_per_line) * sizeof(long);
	lm->lun_bitmap_len = BITS_TO_LONGS(geo->nr_luns) * sizeof(long);
	lm->high_thrs = lm->sec_per_line / 2;
	lm->mid_thrs = lm->sec_per_line / 4;

	/* Calculate necessary pages for smeta. See comment over struct
	 * line_smeta definition
	 */
	lm->smeta_len = sizeof(struct line_smeta) +
				PBLK_LINE_NR_LUN_BITMAP * lm->lun_bitmap_len;

	i = 1;
add_smeta_page:
	lm->smeta_sec = i * geo->sec_per_pl;
	lm->smeta_len = lm->smeta_sec * geo->sec_size;

	smeta_len = sizeof(struct line_smeta) +
				PBLK_LINE_NR_LUN_BITMAP * lm->lun_bitmap_len;
	if (smeta_len > lm->smeta_len) {
		i++;
		goto add_smeta_page;
	}

	/* Calculate necessary pages for emeta. See comment over struct
	 * line_emeta definition
	 */
	i = 1;
add_emeta_page:
	lm->emeta_sec = i * geo->sec_per_pl;
	lm->emeta_len = lm->emeta_sec * geo->sec_size;

	emeta_len = calc_emeta_len(pblk, lm);
	if (emeta_len > lm->emeta_len) {
		i++;
		goto add_emeta_page;
	}
	lm->emeta_bb = geo->nr_luns - i;

	l_mg->nr_lines = geo->blks_per_lun;
	l_mg->log_line = l_mg->data_line = NULL;
	l_mg->l_seq_nr = l_mg->d_seq_nr = 0;
	l_mg->nr_free_lines = 0;
	bitmap_zero(&l_mg->meta_bitmap, PBLK_DATA_LINES);

	/* smeta is always small enough to fit on a kmalloc memory allocation,
	 * emeta depends on the number of LUNs allocated to the pblk instance
	 */
	l_mg->smeta_alloc_type = PBLK_KMALLOC_META;
	for (i = 0; i < PBLK_DATA_LINES; i++) {
		l_mg->sline_meta[i].meta = kmalloc(lm->smeta_len, GFP_KERNEL);
		if (!l_mg->sline_meta[i].meta)
			while (--i >= 0) {
				kfree(l_mg->sline_meta[i].meta);
				ret = -ENOMEM;
				goto fail;
			}
	}

	if (lm->emeta_len > KMALLOC_MAX_CACHE_SIZE) {
		l_mg->emeta_alloc_type = PBLK_VMALLOC_META;

		for (i = 0; i < PBLK_DATA_LINES; i++) {
			l_mg->eline_meta[i].meta = vmalloc(lm->emeta_len);
			if (!l_mg->eline_meta[i].meta)
				while (--i >= 0) {
					vfree(l_mg->eline_meta[i].meta);
					ret = -ENOMEM;
					goto fail;
				}
		}

		l_mg->gc_meta.meta = vmalloc(lm->emeta_len);
		if (!l_mg->gc_meta.meta) {
			for (i = 0; i < PBLK_DATA_LINES; i++) {
				kfree(l_mg->sline_meta[i].meta);
				vfree(l_mg->eline_meta[i].meta);
			}
			ret = -ENOMEM;
			goto fail;
		}
	} else {
		l_mg->emeta_alloc_type = PBLK_KMALLOC_META;

		for (i = 0; i < PBLK_DATA_LINES; i++) {
			l_mg->eline_meta[i].meta =
					kmalloc(lm->emeta_len, GFP_KERNEL);
			if (!l_mg->eline_meta[i].meta)
				while (--i >= 0) {
					kfree(l_mg->eline_meta[i].meta);
					ret = -ENOMEM;
					goto fail;
				}
		}

		l_mg->gc_meta.meta = kmalloc(lm->emeta_len, GFP_KERNEL);
		if (!l_mg->gc_meta.meta) {
			for (i = 0; i < PBLK_DATA_LINES; i++) {
				kfree(l_mg->sline_meta[i].meta);
				kfree(l_mg->eline_meta[i].meta);
				ret = -ENOMEM;
				goto fail;
			}
		}
	}

	l_mg->bb_template = kzalloc(lm->sec_bitmap_len, GFP_KERNEL);
	if (!l_mg->bb_template)
		goto fail_free_meta;

	l_mg->bb_aux = kzalloc(lm->sec_bitmap_len, GFP_KERNEL);
	if (!l_mg->bb_aux)
		goto fail_free_bb_template;

	bb_distance = (geo->nr_luns) * geo->sec_per_pl;
	for (i = 0; i < lm->sec_per_line; i += bb_distance)
		bitmap_set(l_mg->bb_template, i, geo->sec_per_pl);

	INIT_LIST_HEAD(&l_mg->free_list);
	INIT_LIST_HEAD(&l_mg->corrupt_list);
	INIT_LIST_HEAD(&l_mg->bad_list);
	INIT_LIST_HEAD(&l_mg->gc_full_list);
	INIT_LIST_HEAD(&l_mg->gc_high_list);
	INIT_LIST_HEAD(&l_mg->gc_mid_list);
	INIT_LIST_HEAD(&l_mg->gc_low_list);
	INIT_LIST_HEAD(&l_mg->gc_empty_list);

	l_mg->gc_lists[0] = &l_mg->gc_high_list;
	l_mg->gc_lists[1] = &l_mg->gc_mid_list;
	l_mg->gc_lists[2] = &l_mg->gc_low_list;

	spin_lock_init(&l_mg->free_lock);
	spin_lock_init(&l_mg->gc_lock);

	pblk->rl.free_blocks = geo->blks_per_lun * geo->nr_luns;
	pblk->capacity = geo->sec_per_lun * geo->nr_luns;
	pblk->rl.total_blocks = pblk->rl.nr_secs = 0;

	pblk->lines = kcalloc(l_mg->nr_lines, sizeof(struct pblk_line),
								GFP_KERNEL);
	if (!pblk->lines)
		goto fail_free_bb_aux;

	for (i = 0; i < l_mg->nr_lines; i++) {
		line = &pblk->lines[i];

		line->pblk = pblk;
		line->id = i;
		line->type = PBLK_LINETYPE_FREE;
		line->state = PBLK_LINESTATE_FREE;
		line->gc_group = PBLK_LINEGC_NONE;
		spin_lock_init(&line->lock);

		nr_bad_blks = pblk_bb_line(pblk, line);
		if (nr_bad_blks < 0 || nr_bad_blks > lm->blk_per_line)
			goto fail_free_lines;

		pblk->rl.free_blocks -= nr_bad_blks;
		pblk->capacity -= nr_bad_blks * geo->sec_per_blk;

		line->blk_in_line = lm->blk_per_line - nr_bad_blks;
		if (!line->blk_in_line) {
			line->state = PBLK_LINESTATE_BAD;
			continue;
		}

		pblk->rl.total_blocks += line->blk_in_line;
		pblk->rl.nr_secs += (line->blk_in_line * geo->sec_per_blk);

		l_mg->nr_free_lines++;
		list_add_tail(&line->list, &l_mg->free_list);
	}

	/* Cleanup per-LUN bad block lists - managed within lines on run-time */
	for (i = 0; i < geo->nr_luns; i++)
		kfree(pblk->luns[i].bb_list);

	return 0;
fail_free_lines:
	kfree(pblk->lines);
fail_free_bb_aux:
	kfree(l_mg->bb_aux);
fail_free_bb_template:
	kfree(l_mg->bb_template);
fail_free_meta:
	pblk_mfree(l_mg->gc_meta.meta, l_mg->emeta_alloc_type);
	for (i = 0; i < PBLK_DATA_LINES; i++) {
		pblk_mfree(l_mg->sline_meta[i].meta, l_mg->smeta_alloc_type);
		pblk_mfree(l_mg->eline_meta[i].meta, l_mg->emeta_alloc_type);
	}
fail:
	for (i = 0; i < geo->nr_luns; i++)
		kfree(pblk->luns[i].bb_list);

	return ret;
}

static int pblk_writer_init(struct pblk *pblk)
{
	setup_timer(&pblk->wtimer, pblk_write_timer_fn, (unsigned long)pblk);
	mod_timer(&pblk->wtimer, jiffies + msecs_to_jiffies(100));

	pblk->ts_writer = kthread_create(pblk_write_ts, pblk, "pblk-writer");

	return 0;
}

static void pblk_writer_stop(struct pblk *pblk)
{
	if (pblk->ts_writer)
		kthread_stop(pblk->ts_writer);
	del_timer(&pblk->wtimer);
}

static void pblk_free(struct pblk *pblk)
{
	pblk_writer_stop(pblk);
	pblk_luns_free(pblk);
	pblk_lines_free(pblk);
	pblk_line_meta_free(pblk);
	pblk_core_free(pblk);
	pblk_l2p_free(pblk);

    kfree(pblk->chnl_inf);
    vfree(rqst);
	kfree(pblk);
}

static void pblk_tear_down(struct pblk *pblk)
{
	pblk_flush_writer(pblk);
	pblk_rb_sync_l2p(&pblk->rwb);

	if (pblk_rb_tear_down_check(&pblk->rwb)) {
		pr_err("pblk: write buffer error on tear down\n");
		return;
	}

	pr_debug("pblk: consistent tear down\n");
}

static void pblk_exit(void *private)
{
	struct pblk *pblk = private;

	down_write(&pblk_lock);
	flush_workqueue(pblk->gc_wq);
	pblk_tear_down(pblk);
	pblk_gc_exit(pblk);
	pblk_free(pblk);
	up_write(&pblk_lock);
}

static sector_t pblk_capacity(void *private)
{
	struct pblk *pblk = private;
	sector_t provisioned;

	provisioned = pblk->capacity;
	sector_div(provisioned, 10);
	return provisioned * 9 * NR_PHY_IN_LOG;
}

static void *pblk_init(struct nvm_tgt_dev *dev, struct gendisk *tdisk)
{
	struct nvm_geo *geo = &dev->geo;
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct pblk *pblk;
    int i;
	int ret = 0;

	if (dev->identity.dom & NVM_RSP_L2P) {
		pr_err("pblk: device-side L2P table not supported. (%x)\n",
							dev->identity.dom);
		return ERR_PTR(-EINVAL);
	}

	pblk = kzalloc(sizeof(struct pblk), GFP_KERNEL);
	if (!pblk)
		return ERR_PTR(-ENOMEM);

	pblk->dev = dev;
	pblk->disk = tdisk;

	spin_lock_init(&pblk->trans_lock);
	spin_lock_init(&pblk->lock);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&pblk->inflight_writes, 0);
	atomic_set(&pblk->padded_writes, 0);
	atomic_set(&pblk->nr_flush, 0);
	atomic_set(&pblk->req_writes, 0);
	atomic_set(&pblk->sub_writes, 0);
	atomic_set(&pblk->sync_writes, 0);
	atomic_set(&pblk->compl_writes, 0);
	atomic_set(&pblk->inflight_meta, 0);
	atomic_set(&pblk->compl_meta, 0);
	atomic_set(&pblk->inflight_reads, 0);
	atomic_set(&pblk->sync_reads, 0);
	atomic_set(&pblk->recov_writes, 0);
	atomic_set(&pblk->recov_gc_writes, 0);
	atomic_set(&pblk->requeued_writes, 0);
    atomic_set(&pblk->nr_cc_rds, 0);
    atomic_set(&pblk->nr_tgt_rds, 0);
    atomic_set(&pblk->nr_tgt_user_rds, 0);
    atomic_set(&pblk->nr_tgt_wrs, 0);
    atomic_set(&pblk->nr_tgt_ers, 0);
    atomic_set(&pblk->nr_tt_busy, 0);
    atomic_set(&pblk->tos_rqd_id, 0);
    atomic_set(&pblk->tos_nr_type1_errs, 0);
    atomic_set(&pblk->tos_nr_type2_errs, 0);
    atomic_set(&pblk->tos_nr_type1_cors, 0);
    atomic_set(&pblk->tos_nr_type2_cors, 0);
#endif

    pblk->chnl_inf = kmalloc(sizeof(struct chnl_inf) * geo->nr_chnls, GFP_KERNEL);
    for (i = 0; i < geo->nr_chnls; i++) {
        atomic_set(&pblk->chnl_inf[i].inf_rds, 0);
        atomic_set(&pblk->chnl_inf[i].inf_rd_pgs, 0);
        atomic_set(&pblk->chnl_inf[i].inf_wrs, 0);
        atomic_set(&pblk->chnl_inf[i].inf_ers, 0);
    }

    rqst = vmalloc(sizeof(struct pinfo) * MAX_PINFO);
    if (!rqst) {
        pr_err("Coperd, cannot create the big request array!\n");
        goto fail;
    }

	ret = pblk_luns_init(pblk, dev->luns);
	if (ret) {
		pr_err("pblk: could not initialize luns\n");
		goto fail;
	}

	ret = pblk_lines_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize lines\n");
		goto fail_free_luns;
	}

	ret = pblk_core_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize core\n");
		goto fail_free_line_meta;
	}

	ret = pblk_lines_configure(pblk);
	if (ret) {
		pr_err("pblk: could not configure lines\n");
		goto fail_free_core;
	}

	ret = pblk_l2p_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize maps\n");
		goto fail_free_lines;
	}

	ret = pblk_writer_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize write thread\n");
		goto fail_free_l2p;
	}

	ret = pblk_gc_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize gc\n");
		goto fail_stop_writer;
	}

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	blk_queue_write_cache(tqueue, true, false);

	tqueue->limits.discard_granularity = geo->pgs_per_blk * geo->pfpg_size;
	tqueue->limits.discard_alignment = 0;
	blk_queue_max_discard_sectors(tqueue, UINT_MAX >> 9);
	tqueue->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, tqueue);

	pr_info("pblk init: luns:%u, lines:%d, secs:%llu, buf entries:%u\n",
			geo->nr_luns, pblk->l_mg.nr_lines,
			(unsigned long long)pblk->rl.nr_secs,
			pblk->rwb.nr_entries);

	wake_up_process(pblk->ts_writer);
	return pblk;

fail_stop_writer:
	pblk_writer_stop(pblk);
fail_free_l2p:
	pblk_l2p_free(pblk);
fail_free_lines:
	pblk_lines_free(pblk);
fail_free_core:
	pblk_core_free(pblk);
fail_free_line_meta:
	pblk_line_meta_free(pblk);
fail_free_luns:
	pblk_luns_free(pblk);
fail:
	kfree(pblk);
	return ERR_PTR(ret);
}

/* physical block device target */
static struct nvm_tgt_type tt_pblk = {
	.name		= "pblk",
	.version	= {1, 0, 0},

	.make_rq	= pblk_make_rq,
	.capacity	= pblk_capacity,

	.init		= pblk_init,
	.exit		= pblk_exit,

	.sysfs_init	= pblk_sysfs_init,
	.sysfs_exit	= pblk_sysfs_exit,
};

static int __init pblk_module_init(void)
{
	return nvm_register_tgt_type(&tt_pblk);
}

static void pblk_module_exit(void)
{
	nvm_unregister_tgt_type(&tt_pblk);
}

module_init(pblk_module_init);
module_exit(pblk_module_exit);
MODULE_AUTHOR("Javier Gonzalez <javier@cnexlabs.com>");
MODULE_AUTHOR("Matias Bjorling <matias@cnexlabs.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Physical Block-Device for Open-Channel SSDs");
