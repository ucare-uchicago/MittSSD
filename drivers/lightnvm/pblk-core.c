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
 * pblk-core.c - pblk's core functionality
 *
 */

#include "pblk.h"
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/tick.h>

static void pblk_mark_bb(struct pblk *pblk, struct pblk_line *line,
			 struct ppa_addr *ppa)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    int pos = pblk_ppa_to_pos(geo, *ppa);

    pr_debug("pblk: erase failed: line:%d, pos:%d\n", line->id, pos);
    inc_stat(pblk, &pblk->erase_failed, 0);

    if (test_and_set_bit(pos, line->blk_bitmap))
        pr_err("pblk: attempted to erase bb: line:%d, pos:%d\n",
                line->id, pos);

    pblk_line_run_ws(pblk, ppa, pblk_line_mark_bb);
}

static void down_perlun_inf_er(struct pblk *pblk, struct nvm_rq *rqd)
{
    int lun_id;
    struct pblk_lun *tlun;
    int inf_er;
    int pch;
    ktime_t now = ktime_get();
    s64 lat_diff;
    unsigned long flag;

    rqd->tlat_us = ktime_to_us(ktime_sub(now, rqd->stime));
    lat_diff = rqd->plat_us - rqd->tlat_us;
    lun_id = pblk_ppa_to_lun(pblk, rqd->ppa_addr);
    tlun = &pblk->luns[lun_id];
    pch = tlun->bppa.g.ch;
    spin_lock_irqsave(&tlun->lock, flag);
    if (lat_diff > 0)
        tlun->next_avail_time = ktime_sub_us(tlun->next_avail_time, lat_diff);
    else {
        lat_diff = -1 * lat_diff;
        tlun->next_avail_time = ktime_add_us(tlun->next_avail_time, lat_diff);
    }
    spin_unlock_irqrestore(&tlun->lock, flag);
    tlun->last_er_lat_us = ktime_to_us(ktime_sub(now, tlun->last_er_stime));
    tos_pr_rqd(pblk, rqd, rqd->ppa_addr, 1);
    atomic_dec(&tlun->inf_er);
    atomic_dec(&pblk->chnl_inf[pch].inf_ers);
    inf_er = atomic_read(&tlun->inf_er);
    WARN_ON(inf_er < 0);
#if 0
    if (pblk->tos_pr_lat == TOS_PR_ERONLY || pblk->tos_pr_lat == TOS_PR_ALL)
        pr_debug("Coperd,rqd-er-e,%d,%u,%d,%d,%u\n", rqd->id, rqd->nr_ppas,
                rqd->plat_us, rqd->tlat_us, rqd->ebusy);
#endif
}

static void __pblk_end_io_erase(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct pblk_line *line;

	line = &pblk->lines[pblk_ppa_to_line(rqd->ppa_addr)];
	atomic_dec(&line->left_seblks);

    down_perlun_inf_er(pblk, rqd);

	if (rqd->error) {
		struct ppa_addr *ppa;

		ppa = kmalloc(sizeof(struct ppa_addr), GFP_ATOMIC);
		if (!ppa)
			return;

		*ppa = rqd->ppa_addr;
		pblk_mark_bb(pblk, line, ppa);
	}
}

/* Erase completion assumes that only one block is erased at the time */
static void pblk_end_io_erase(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;

	__pblk_end_io_erase(pblk, rqd);
	mempool_free(rqd, pblk->r_rq_pool);
}

static void pblk_end_io_sync(struct nvm_rq *rqd)
{
	struct completion *waiting = rqd->private;

	complete(waiting);
}

static void pblk_page_invalidate(struct pblk *pblk, struct ppa_addr ppa)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list = NULL;
	struct pblk_line *line;
	u64 paddr;
	int line_id;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nvm_addr_in_cache(ppa));
	BUG_ON(ppa_empty(ppa));
#endif

	line_id = pblk_ppa_to_line(ppa);
	line = &pblk->lines[line_id];

	/* Lines being reclaimed (GC'ed) do not need to be invalidated. Before
	 * the L2P table is modified with valid reclaimed sectors a check is
	 * done to endure that newer updates are not overwritten.
	 */
	spin_lock(&line->lock);
	if (line->state == PBLK_LINESTATE_GC ||
					line->state == PBLK_LINESTATE_FREE) {
		spin_unlock(&line->lock);
		return;
	}

	paddr = pblk_ppa_to_line_addr(pblk, ppa);
	if (test_and_set_bit(paddr, line->invalid_bitmap)) {
		WARN_ONCE(1, "pblk: double invalidate\n");
		spin_unlock(&line->lock);
		return;
	}
	line->vsc--;

	if (line->state == PBLK_LINESTATE_CLOSED)
		move_list = pblk_line_gc_list(pblk, line);
	spin_unlock(&line->lock);

	if (move_list) {
		spin_lock(&l_mg->gc_lock);
		list_move_tail(&line->list, move_list);
		spin_unlock(&l_mg->gc_lock);
	}
}

static void pblk_invalidate_range(struct pblk *pblk, sector_t slba,
				  unsigned int nr_secs)
{
	sector_t lba;

	spin_lock(&pblk->trans_lock);
	for (lba = slba; lba < slba + nr_secs; lba++) {
		struct ppa_addr *ppa = &pblk->trans_map[lba];

		if (!nvm_addr_in_cache(*ppa) && !ppa_empty(*ppa))
			pblk_page_invalidate(pblk, *ppa);
		ppa_set_empty(ppa);
	}
	spin_unlock(&pblk->trans_lock);
}

struct nvm_rq *pblk_alloc_rqd(struct pblk *pblk, int rw)
{
	mempool_t *pool;
	struct nvm_rq *rqd;
	int rq_size;

	if (rw == WRITE) {
		pool = pblk->w_rq_pool;
		rq_size = pblk_w_rq_size;
	} else {
		pool = pblk->r_rq_pool;
		rq_size = pblk_r_rq_size;
	}

	rqd = mempool_alloc(pool, GFP_KERNEL);
	if (!rqd)
		return ERR_PTR(-ENOMEM);

	memset(rqd, 0, rq_size);
	return rqd;
}

void pblk_free_rqd(struct pblk *pblk, struct nvm_rq *rqd, int rw)
{
	mempool_t *pool;

	if (rw == WRITE)
		pool = pblk->w_rq_pool;
	else
		pool = pblk->r_rq_pool;

	mempool_free(rqd, pool);
}

void pblk_print_failed_rqd(struct pblk *pblk, struct nvm_rq *rqd, int error)
{
	int bit = -1;

	if (rqd->nr_ppas ==  1) {
		print_ppa(&rqd->ppa_addr, "rqd", error);
		return;
	}

	while ((bit = find_next_bit((void *)&rqd->ppa_status, rqd->nr_ppas,
						bit + 1)) < rqd->nr_ppas) {
		print_ppa(&rqd->ppa_list[bit], "rqd", error);
	}

	pr_err("error:%d, ppa_status:%llx\n", error, rqd->ppa_status);
}

void pblk_bio_free_pages(struct pblk *pblk, struct bio *bio, int off,
			 int nr_pages)
{
	struct bio_vec bv;
	int i;

	WARN_ON(off + nr_pages != bio->bi_vcnt);

	bio_advance(bio, off * PBLK_EXPOSED_PAGE_SIZE);
	for (i = off; i < nr_pages + off; i++) {
		bv = bio->bi_io_vec[i];
		mempool_free(bv.bv_page, pblk->page_pool);
	}
}

int pblk_bio_add_pages(struct pblk *pblk, struct bio *bio, gfp_t flags,
		       int nr_pages)
{
	struct request_queue *q = pblk->dev->q;
	struct page *page;
	int i, ret;

	for (i = 0; i < nr_pages; i++) {
		page = mempool_alloc(pblk->page_pool, flags);
		if (!page)
			goto err;

		ret = bio_add_pc_page(q, bio, page, PBLK_EXPOSED_PAGE_SIZE, 0);
		if (ret != PBLK_EXPOSED_PAGE_SIZE) {
			pr_err("pblk: could not add page to bio\n");
			mempool_free(page, pblk->page_pool);
			goto err;
		}
	}

	return 0;
err:
	pblk_bio_free_pages(pblk, bio, 0, i - 1);
	return -1;
}

void pblk_write_timer_fn(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	/* kick the write thread every tick to flush outstanding data */
	pblk_write_kick(pblk);
}

void pblk_end_bio_sync(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	complete(waiting);
}

void pblk_flush_writer(struct pblk *pblk)
{
	struct bio *bio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio)
		return;

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_OP_FLUSH);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_bio_sync;

	ret = pblk_write_to_cache(pblk, bio, 0);
	if (ret == NVM_IO_OK)
		wait_for_completion_io(&wait);
	else if (ret != NVM_IO_DONE)
		pr_err("pblk: tear down bio failed\n");

	if (bio->bi_error)
		pr_err("pblk: flush sync write failed (%u)\n", bio->bi_error);

	bio_put(bio);
}

struct list_head *pblk_line_gc_list(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list = NULL;

	if (!line->vsc) {
		if (line->gc_group != PBLK_LINEGC_FULL) {
			line->gc_group = PBLK_LINEGC_FULL;
			move_list = &l_mg->gc_full_list;
		}
	} else if (line->vsc < lm->mid_thrs) {
		if (line->gc_group != PBLK_LINEGC_HIGH) {
			line->gc_group = PBLK_LINEGC_HIGH;
			move_list = &l_mg->gc_high_list;
		}
	} else if (line->vsc < lm->high_thrs) {
		if (line->gc_group != PBLK_LINEGC_MID) {
			line->gc_group = PBLK_LINEGC_MID;
			move_list = &l_mg->gc_mid_list;
		}
	} else if (line->vsc < line->sec_in_line) {
		if (line->gc_group != PBLK_LINEGC_LOW) {
			line->gc_group = PBLK_LINEGC_LOW;
			move_list = &l_mg->gc_low_list;
		}
	} else if (line->vsc == line->sec_in_line) {
		if (line->gc_group != PBLK_LINEGC_EMPTY) {
			line->gc_group = PBLK_LINEGC_EMPTY;
			move_list = &l_mg->gc_empty_list;
		}
	} else {
		line->state = PBLK_LINESTATE_CORRUPT;
		line->gc_group = PBLK_LINEGC_NONE;
		move_list =  &l_mg->corrupt_list;
		pr_err("pblk: corrupted vsc for line %d, vsc:%d (%d/%d/%d)\n",
						line->id, line->vsc,
						line->sec_in_line,
						lm->high_thrs, lm->mid_thrs);
	}

	return move_list;
}

void pblk_discard(struct pblk *pblk, struct bio *bio)
{
	sector_t slba = pblk_get_lba(bio);
	sector_t nr_secs = pblk_get_secs(bio);

	pblk_invalidate_range(pblk, slba, nr_secs);
}

struct ppa_addr pblk_get_lba_map(struct pblk *pblk, sector_t lba)
{
	struct ppa_addr ppa;

	spin_lock(&pblk->trans_lock);
	ppa = pblk->trans_map[lba];
	spin_unlock(&pblk->trans_lock);

	return ppa;
}

void pblk_log_write_err(struct pblk *pblk, struct nvm_rq *rqd)
{
	inc_stat(pblk, &pblk->write_failed, 1);
#ifdef CONFIG_NVM_DEBUG
	pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif
}

void pblk_log_read_err(struct pblk *pblk, struct nvm_rq *rqd)
{
	switch (rqd->error) {
	case NVM_RSP_WARN_HIGHECC:
		inc_stat(pblk, &pblk->read_high_ecc, 1);
		break;
	case NVM_RSP_ERR_FAILECC:
		inc_stat(pblk, &pblk->read_failed, 1);
		break;
	case NVM_RSP_ERR_FAILCRC:
		inc_stat(pblk, &pblk->read_failed, 1);
		break;
	case NVM_RSP_ERR_EMPTYPAGE:
		inc_stat(pblk, &pblk->read_empty, 1);
		break;
	default:
		pr_err("pblk: unknown read error:%d\n", rqd->error);
	}
#ifdef CONFIG_NVM_DEBUG
    pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif
}

static void up_perlun_inf_wr(struct pblk *pblk, struct nvm_rq *rqd)
{
    int i;
    int min = pblk->min_write_pgs;
    struct pblk_lun *tlun;
    struct ppa_addr *ppa_list;
    int lun_id;
    int pch, ppg;
    ktime_t now = ktime_get();
    u64 coef_wr;
    s64 wait_time = 0;

    ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
    atomic_inc(&pblk->nr_tgt_wrs);
    /* Coperd: up per-lun counters */
    for (i = 0; i < rqd->nr_ppas; i += min) {
        lun_id = pblk_ppa_to_lun(pblk, ppa_list[i]);
        tlun = &pblk->luns[lun_id];
        pch = tlun->bppa.g.ch;
        ppg = ppa_list[i].g.pg;
        if (pblk->wr_lat_tbl[ppg] == 0) {
            coef_wr = pblk->coef_lp_wr;
        } else {
            coef_wr = pblk->coef_up_wr;
        }

        spin_lock(&tlun->lock);
        if (ktime_after(tlun->next_avail_time, now)) {
            /* Coperd: queue this request up */
            tlun->next_avail_time = ktime_add_us(tlun->next_avail_time, coef_wr);
            wait_time = ktime_to_us(ktime_sub(tlun->next_avail_time, now));
        } else {
            tlun->next_avail_time = ktime_add_us(now, coef_wr);
            wait_time = coef_wr;
        }
        spin_unlock(&tlun->lock);

        atomic_inc(&tlun->inf_wr);
        atomic_inc(&pblk->chnl_inf[pch].inf_wrs);
        atomic_inc(&tlun->nr_tt_wrs);
        tlun->last_wr_stime = now;
        //tos_pr_rqd(pblk, rqd, ppa_list[i], 0);
        tlun->last_wr_addr = ppa_list[i];
        if (rqd->plat_us < wait_time)
            rqd->plat_us = wait_time;
    }
}

void tos_pr_rqd(struct pblk *pblk, struct nvm_rq *rqd, struct ppa_addr p, int se)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    struct nvm_dev_map *dev_map = dev->map;
    struct nvm_ch_map *ch_map;
    int lun_id;
    struct pblk_lun *tlun;
    int lun_off;
    int ch;
    int lun;
    char s[16] = {'\0'};
    int do_pr = 0;
    int tch, tlun_id;
    ktime_t pt;

    if (pblk->tos_pr_lat == 0)
        return;

    lun_id = pblk_ppa_to_lun(pblk, p);
    ch_map = &dev_map->chnls[p.g.ch];
    lun_off = ch_map->lun_offs[p.g.lun];
    ch = p.g.ch + ch_map->ch_off;
    lun = p.g.lun + lun_off;

    switch (rqd->opcode) {
        case NVM_OP_PREAD:
            if (pblk->tos_pr_lat == TOS_PR_RDONLY)
                do_pr = 1;
            strcpy(s, "subread-");
            lun_id = p.g.lun;
            break;
        case NVM_OP_PWRITE:
            if (pblk->tos_pr_lat == TOS_PR_WRONLY)
                do_pr = 1;
            strcpy(s, "subwrite-");
            break;
        case NVM_OP_ERASE:
            if (pblk->tos_pr_lat == TOS_PR_ERONLY)
                do_pr = 1;
            strcpy(s, "erase-");
            break;
    }

    if (pblk->tos_pr_lat == TOS_PR_ALL)
        do_pr = 1;

    if (!do_pr)
        return;

    switch (se) {
        case 0:
            strcat(s, "s");
            break;
        case 1:
            strcat(s, "e");
            break;
    }

    tlun = &pblk->luns[lun_id];

    switch (rqd->opcode) {
        case NVM_OP_PREAD:
            tch = lun_id / geo->luns_per_chnl;
            tlun_id = lun_id % geo->luns_per_chnl;
            ch_map = &dev_map->chnls[tch];
            lun_off = ch_map->lun_offs[tlun_id];

            pt = tlun->last_rd_lat_us;
            if (se == 0)
                pt = ktime_to_us(tlun->last_rd_stime);
            pr_debug("Coperd,%s,%d,(%u %d),%d,%lld,%lld\n", s, rqd->id,
                    tch + ch_map->ch_off, tlun_id + lun_off,
                    rqd->lun_dist[lun_id], tlun->plat_us, pt);
            break;
        case NVM_OP_PWRITE:
            //pt = tlun->last_wr_lat_us;
            pt = rqd->plat_us;
            if (se == 0)
                pt = ktime_to_us(tlun->last_wr_stime);
            pr_debug("Coperd,%s,%d,(%u %u %u %u %u %u),%lld,%lld\n", s, rqd->id, ch, lun,
                    p.g.pl, p.g.blk, p.g.pg, p.g.sec, pt, rqd->tlat_us);
            break;
        case NVM_OP_ERASE:
            //pt = tlun->last_er_lat_us;
            pt = rqd->plat_us;
            if (se == 0)
                pt = ktime_to_us(tlun->last_er_stime);
            pr_debug("Coperd,%s,%d,(%u %u %u %u %u %u),%lld,%lld\n", s, rqd->id, ch, lun,
                    p.g.pl, p.g.blk, p.g.pg, p.g.sec, pt, rqd->tlat_us);
            break;
    }
}

void down_perlun_inf_wr(struct pblk *pblk, struct nvm_rq *rqd)
{
    int i;
    int min = pblk->min_write_pgs;
    struct pblk_lun *tlun;
    struct ppa_addr *ppa_list;
    ktime_t now = ktime_get();
    s64 lat_diff;
    int pch;
    int inf_rd;
    int lun_id;
    unsigned long flag;

    ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
    rqd->tlat_us = ktime_to_us(ktime_sub(now, rqd->stime));
    for (i = 0; i < rqd->nr_ppas; i += min) {
        lun_id = pblk_ppa_to_lun(pblk, ppa_list[i]);
        tlun = &pblk->luns[lun_id];
        pch = tlun->bppa.g.ch;

        lat_diff = rqd->plat_us - rqd->tlat_us;

        spin_lock_irqsave(&tlun->lock, flag);
        if (lat_diff > 0) {
            tlun->next_avail_time = ktime_sub_us(tlun->next_avail_time, lat_diff);
            //pr_debug("Coperd,diff=%d >>>>> 0, writes end,up next_avail_time=%lld\n", lat_diff,tlun->next_avail_time);
        } else {
            lat_diff = -1 * lat_diff;
            tlun->next_avail_time = ktime_add_us(tlun->next_avail_time, lat_diff);
            //pr_debug("Coperd,diff=%d <<<<<<< 0, writes end,up next_avail_time=%lld\n", lat_diff,tlun->next_avail_time);
        }
        spin_unlock_irqrestore(&tlun->lock, flag);

        tlun->last_wr_lat_us = ktime_to_us(ktime_sub(now, tlun->last_wr_stime));
        tos_pr_rqd(pblk, rqd, ppa_list[i], 1);
        atomic_dec(&tlun->inf_wr);
        atomic_dec(&pblk->chnl_inf[pch].inf_wrs);
        inf_rd = atomic_read(&tlun->inf_wr);
        WARN_ON(inf_rd < 0);
    }

    if (pblk->tos_pr_lat == TOS_PR_WRONLY || pblk->tos_pr_lat == TOS_PR_ALL)
        pr_debug("Coperd,rqd-wr-e,%d,%u,%lld,%lld,%d\n", rqd->id, rqd->nr_ppas,
                rqd->plat_us, rqd->tlat_us, rqd->ebusy);
}

static void up_perlun_inf_er(struct pblk *pblk, struct nvm_rq *rqd)
{
    int lun_id;
    struct pblk_lun *tlun;
    int inf_er;
    int pch;
    ktime_t now = ktime_get();
    u64 coef_er = pblk->coef_er;

    atomic_inc(&pblk->nr_tgt_ers);
    lun_id = pblk_ppa_to_lun(pblk, rqd->ppa_addr);
    tlun = &pblk->luns[lun_id];
    pch = tlun->bppa.g.ch;
    //tos_pr_rqd(pblk, rqd, rqd->ppa_addr, 0);

    spin_lock(&tlun->lock);
    if (ktime_after(tlun->next_avail_time, now)) {
        /* Coperd: queue this request up */
        tlun->next_avail_time = ktime_add_us(tlun->next_avail_time, coef_er);
        coef_er = ktime_to_us(ktime_sub(tlun->next_avail_time, now));
    } else {
        tlun->next_avail_time = ktime_add_us(now, coef_er);
    }
    spin_unlock(&tlun->lock);

    tlun->last_er_stime = now;
    atomic_inc(&tlun->nr_tt_ers);
    atomic_inc(&tlun->inf_er);
    atomic_inc(&pblk->chnl_inf[pch].inf_ers);
    inf_er = atomic_read(&tlun->inf_er);
    WARN_ON(inf_er <= 0);
    rqd->plat_us = coef_er;
    //pr_debug("Coperd,erase,rqd->plat_us=%d,coef_er=%d\n", rqd->plat_us, coef_er);
}

static int is_user_rq_dev(struct nvm_rq *rqd)
{
    struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
    return (rqd->type == PBLK_IOTYPE_USER && r_ctx->lun_bitmap);
}

static int tos_is_type1_err(struct pblk *pblk, struct nvm_rq *rqd)
{
    return is_user_rq_dev(rqd) && rqd->ebusy == 0 &&
        rqd->tlat_us > pblk->tos_tgt_lat;
}

static int tos_is_type2_err(struct pblk *pblk, struct nvm_rq *rqd)
{
    return is_user_rq_dev(rqd) && rqd->ebusy == 1 &&
        rqd->tlat_us < pblk->tos_tgt_lat;
}

static int tos_is_type1_corr(struct pblk *pblk, struct nvm_rq *rqd)
{
    return is_user_rq_dev(rqd) && rqd->ebusy == 0 &&
        rqd->tlat_us < pblk->tos_tgt_lat;
}

static int tos_is_type2_corr(struct pblk *pblk, struct nvm_rq *rqd)
{
    return is_user_rq_dev(rqd) && rqd->ebusy == 1 &&
        rqd->tlat_us > pblk->tos_tgt_lat;
}

void down_perlun_inf_rd(struct pblk *pblk, struct nvm_rq *rqd)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    int nr_luns = geo->nr_luns;
    struct pblk_lun *tlun;
    unsigned long *lun_bitmap;
    struct ppa_addr *ppa_list;
    struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
    int bit = -1;
    int lun_id, inf_rd;
    ktime_t now = ktime_get();
    int pch;
    int i;
    int type = -1;
    s64 lat_diff = 0;
    unsigned long flag;

    /* Coperd: filter cached reads */
    if (rqd->type == PBLK_IOTYPE_USER && !r_ctx->lun_bitmap)
        return;

    ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
    lun_bitmap = r_ctx->lun_bitmap;

    if (rqd->type != PBLK_IOTYPE_USER) {
        lun_bitmap = kzalloc(pblk->lm.lun_bitmap_len, GFP_KERNEL);
        if (!lun_bitmap) {
            pr_err("pblk: out of memory to create request lun_bitmap\n");
            return;
        }

        for (i = 0; i < rqd->nr_ppas; i++) {
            lun_id = pblk_ppa_to_lun(pblk, ppa_list[i]);
            set_bit(lun_id, lun_bitmap);
        }
    }

    rqd->tlat_us = ktime_to_us(ktime_sub(now, rqd->stime));
    while ((bit = find_next_bit(lun_bitmap, nr_luns, bit + 1)) < nr_luns) {
        int nr_ef_pgs = rqd->lun_dist[bit];
        tlun = &pblk->luns[bit];
        pch = tlun->bppa.g.ch;

        lat_diff = rqd->plat_us - rqd->tlat_us;

        spin_lock_irqsave(&tlun->lock, flag);
        if (lat_diff > 0) {
            tlun->next_avail_time = ktime_sub_us(tlun->next_avail_time, lat_diff);
        } else {
            lat_diff = -1 * lat_diff;
            tlun->next_avail_time = ktime_add_us(tlun->next_avail_time, lat_diff);
        }
        spin_unlock_irqrestore(&tlun->lock, flag);

        atomic_dec(&tlun->inf_rd);
        atomic_dec(&pblk->chnl_inf[pch].inf_rds);
        atomic_sub(nr_ef_pgs, &tlun->inf_rd_pgs);
        atomic_sub(nr_ef_pgs, &pblk->chnl_inf[pch].inf_rd_pgs);
        inf_rd = atomic_read(&tlun->inf_rd);
        WARN_ON(inf_rd < 0);
        //now = ktime_get();
        //tlun->last_rd_lat_us = ktime_to_us(ktime_sub(now, tlun->last_rd_stime));
        tos_pr_rqd(pblk, rqd, tlun->bppa, 1);
#if 0
        list_del_rcu(&rqd->list);
#endif
    }

    if (tos_is_type1_err(pblk, rqd)) {
        atomic_inc(&pblk->tos_nr_type1_errs);
        type = 1;
    } else if (tos_is_type2_err(pblk, rqd)) {
        atomic_inc(&pblk->tos_nr_type2_errs);
        type = 2;
    } else if (tos_is_type1_corr(pblk, rqd)) {
        atomic_inc(&pblk->tos_nr_type1_cors);
        type = 3;
    } else if (tos_is_type2_corr(pblk, rqd)) {
        atomic_inc(&pblk->tos_nr_type2_cors);
        type = 4;
    }

    spin_lock_irqsave(&mt_lock, flag);
    rqst[rq_idx].plat_us = rqd->plat_us;
    rqst[rq_idx].tlat_us = rqd->tlat_us;
    rqst[rq_idx].lat_diff = lat_diff;
    rqst[rq_idx].type = type;
    rqst[rq_idx].ebusy = rqd->ebusy;
    rq_idx++;
    //pr_debug("Coperd,rq_idx=%d,tgt_user_rds=%d,plat_us=%d,tlat_us=%d,lat_diff=%d,type=%d,ebusy=%d\n", rq_idx, atomic_read(&pblk->nr_tgt_user_rds),rqd->plat_us,rqd->tlat_us,lat_diff,type,rqd->ebusy);
    spin_unlock_irqrestore(&mt_lock, flag);

    if (pblk->tos_pr_lat == TOS_PR_RDONLY || pblk->tos_pr_lat == TOS_PR_ALL)
        pr_debug("Coperd,rqd-e,%d,%u,%lld,%lld,%d,%d\n", rqd->id, rqd->nr_ppas,
                rqd->plat_us, rqd->tlat_us, type, rqd->ebusy);

    if (rqd->type != PBLK_IOTYPE_USER)
        kfree(lun_bitmap);

    kfree(rqd->lun_dist);
}

static void tos_dump_freq_info(struct pblk *pblk, struct pblk_lun *tlun, int id)
{
    int i;
    struct nvm_tgt_dev *dev = pblk->dev;
    int nr_tt_rds = atomic_read(&tlun->nr_tt_rds);

    if (pblk->tos_debug && (!(nr_tt_rds % pblk->tos_debug_freq))) {
        pr_debug("/////////////LUN[%s,%d]//////////////\n", dev->name, id);
        pr_debug("Coperd,nr_tt_rds:%d,nr_cc_rds:%d,nr_tt_wrs:%d,nr_tt_ers:%d\n"
                "inf_rd:%d,inf_wr:%d,inf_er:%d", nr_tt_rds,
                atomic_read(&pblk->nr_cc_rds), atomic_read(&tlun->nr_tt_wrs),
                atomic_read(&tlun->nr_tt_ers), atomic_read(&tlun->inf_rd),
                atomic_read(&tlun->inf_wr), atomic_read(&tlun->inf_er));

        for (i = 0; i < WR_SEM_MAX + 1; i++) {
            int freq = atomic_read(&tlun->inf_wr_freq[i]);
            if (!freq)
                continue;
            pr_debug("[%d]:%d,", i, freq);
        }
        pr_debug("\n");
    }
}

/*
 * Coperd: currently it's safe to assume that r_ctx exists for full/partial
 * user reads, what about emeta/smeta reads?
 */
static void up_perlun_inf_rd(struct pblk *pblk, struct nvm_rq *rqd)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    int nr_luns = geo->nr_luns;
    struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
    struct pblk_lun *tlun;
    unsigned long *lun_bitmap = r_ctx->lun_bitmap;
    struct ppa_addr *ppa_list;
    int coef_rd = pblk->coef_rd;
    int bit = -1;
    int lun_id;
    int pch;
    int new_bitmap_flag = 0;
    int cur_inf_wr, inf_rd;
    int i;
    ktime_t now = ktime_get();
    s64 wait_time;
    u64 sub_rqd_lat;

    ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
    rqd->lun_dist = kzalloc(sizeof(int) * nr_luns, GFP_KERNEL);
    /* Coperd: for non-user reads, create the lunbitmap manually here */
    for (i = 0; i < rqd->nr_ppas; i++) {
        lun_id = pblk_ppa_to_lun(pblk, ppa_list[i]);
        rqd->lun_dist[lun_id]++;
        set_bit(lun_id, lun_bitmap);
    }

    if (rqd->type != PBLK_IOTYPE_USER) {
        lun_bitmap = kzalloc(pblk->lm.lun_bitmap_len, GFP_KERNEL);
        if (!lun_bitmap) {
            pr_err("pblk: out of memory to create request lun_bitmap\n");
            return;
        }
        new_bitmap_flag = 1;
    }

    atomic_inc(&pblk->nr_tgt_rds);
    if (is_user_rq_dev(rqd))
        atomic_inc(&pblk->nr_tgt_user_rds);
    while ((bit = find_next_bit(lun_bitmap, nr_luns, bit + 1)) < nr_luns) {
        int nr_ef_pgs = 1;
        /* Coperd: is it possible reading multiple sectors from diff pgs ?? */
        if (rqd->lun_dist[bit] <= geo->sec_per_pg)
            rqd->lun_dist[bit] = 1;
        else
            rqd->lun_dist[bit] = rqd->lun_dist[bit] / geo->sec_per_pg;
        nr_ef_pgs = rqd->lun_dist[bit];

        tlun = &pblk->luns[bit];
        pch = tlun->bppa.g.ch;
#if 0
        list_add_tail_rcu(&rqd->list, &tlun->inf_rqds);
#endif

        sub_rqd_lat = coef_rd * nr_ef_pgs;

        //pr_debug("Coperd,sub_rqd_lat=%d,coef_rd=%d,nr_ef_pgs=%d\n", sub_rqd_lat, coef_rd, nr_ef_pgs);
        wait_time = 0;
        spin_lock(&tlun->lock);
        if (ktime_after(tlun->next_avail_time, now)) {
            /* Coperd: queue this requst up */
            tlun->next_avail_time = ktime_add_us(tlun->next_avail_time,
                    sub_rqd_lat);
            wait_time = ktime_to_us(ktime_sub(tlun->next_avail_time, now));
        } else {
            tlun->next_avail_time = ktime_add_us(now, sub_rqd_lat);
            wait_time = sub_rqd_lat;
        }
        spin_unlock(&tlun->lock);
        //pr_debug("Coperd,after lock,sub_rqd_lat=%d,coef_rd=%d,nr_ef_pgs=%d\n", sub_rqd_lat, coef_rd, nr_ef_pgs);

        /* Coperd: dump freq info every ``tos_debug_freq`` issued reads */
        tos_dump_freq_info(pblk, tlun, bit);
        cur_inf_wr = atomic_read(&tlun->inf_wr);
        atomic_inc(&tlun->inf_wr_freq[cur_inf_wr]);
        atomic_inc(&tlun->nr_tt_rds);
        atomic_inc(&tlun->inf_rd);
        atomic_inc(&pblk->chnl_inf[pch].inf_rds);
        atomic_add(nr_ef_pgs, &tlun->inf_rd_pgs);
        atomic_add(nr_ef_pgs, &pblk->chnl_inf[pch].inf_rd_pgs);
        inf_rd = atomic_read(&tlun->inf_rd);
        WARN_ON(inf_rd <= 0);

        //tlun->last_rd_stime = now;

        if (rqd->plat_us < wait_time)
            rqd->plat_us = wait_time;

        //tos_pr_rqd(pblk, rqd, tlun->bppa, 0);
    }

    //pr_debug("Coperd,read,rqd->plat_us=%d,sub_rqd_lat=%d\n", rqd->plat_us, sub_rqd_lat);

    if (new_bitmap_flag == 1)
        kfree(lun_bitmap);
}

/* Coperd: latency prediction function */
#if 0
static int lat_predict_perlun(struct pblk *pblk, struct pblk_lun *lun,
        struct nvm_rq *rqd)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    struct nvm_dev_map *dev_map = dev->map;
    struct nvm_ch_map *ch_map = &dev_map->chnls[lun->bppa.g.ch];
    int coef_rd = pblk->coef_rd;
    int coef_wr = pblk->coef_lp_wr;
    int coef_er = pblk->coef_er;
    int coef_cc = pblk->coef_cc;
    int pch = lun->bppa.g.ch;
    int chnl_inf_rd_pgs, chnl_inf_wrs;
    int coef_chnl = 1;
    int inf_rd = atomic_read(&lun->inf_rd);
    int inf_rd_pgs = atomic_read(&lun->inf_rd_pgs);
    int inf_wr = atomic_read(&lun->inf_wr);
    int inf_er = atomic_read(&lun->inf_er);
    int nr_luns = geo->nr_luns;
    int plat = coef_rd * rqd->lun_dist[lun->bppa.g.ch * nr_luns + lun->bppa.g.lun];
    s64 rd_remt = 0, wr_remt = 0, er_remt = 0;
    struct ppa_addr inf_wr_addr = lun->last_wr_addr;
    int lat_oft = inf_wr_addr.g.blk * geo->blks_per_lun + inf_wr_addr.g.pg;
    u32 *wr_lat_tbl = lun->wr_lat_tbl;
    int ch, lun_id, lun_off;
    //ktime_t now = ktime_get();
    //struct nvm_rq *pos;
    int chnl_inf_rds;

    chnl_inf_rd_pgs = atomic_read(&pblk->chnl_inf[pch].inf_rd_pgs);
    chnl_inf_rds = atomic_read(&pblk->chnl_inf[pch].inf_rds);
    chnl_inf_wrs = atomic_read(&pblk->chnl_inf[pch].inf_wrs);
    coef_chnl = (chnl_inf_rds + 8 * chnl_inf_wrs) * coef_cc / 2;

    /* Coperd: this would give us one rd latency offset, TOTUNE */
    if (inf_rd >= 1 && inf_rd_pgs >= 1) {
#if 0
        list_for_each_entry_rcu(pos, &lun->inf_rqds, list) {
            int tmp_remt = coef_rd + coef_chnl - ktime_to_us(ktime_sub(now, pos->stime));
            if (tmp_remt > 0)
                rd_remt += tmp_remt;
            break;
        }

        rd_remt = (inf_rd_pgs - 1) * (coef_rd + coef_chnl);
#endif

        rd_remt = inf_rd_pgs * (coef_rd + coef_chnl);
        rd_remt -= ktime_to_us(ktime_sub(now, lun->last_rd_stime));
        if (rd_remt < 0)
            rd_remt = 0;
    }

    if (inf_wr >= 1) {
        if (wr_lat_tbl[lat_oft]) {
            coef_wr = wr_lat_tbl[lat_oft];
        }
        coef_wr = inf_wr * (coef_wr + coef_chnl);
        wr_remt = coef_wr - ktime_to_us(ktime_sub(now, lun->last_wr_stime));
        if (wr_remt < 0)
            wr_remt = 0;
    }

    if (inf_er >= 1) {
        er_remt = coef_er * inf_er;
        er_remt -= ktime_to_us(ktime_sub(now, lun->last_er_stime));
        if (er_remt < 0)
            er_remt = 0;
    }

    plat += rd_remt + wr_remt + er_remt;

    if (pblk->tos_pr_lat == TOS_PR_ALL && inf_wr >= 1) {
        ch_map = &dev_map->chnls[inf_wr_addr.g.ch];
        lun_off = ch_map->lun_offs[inf_wr_addr.g.lun];
        ch = inf_wr_addr.g.ch + ch_map->ch_off;
        lun_id = inf_wr_addr.g.lun + lun_off;
        pr_debug("Coperd,inf-wr,%d,(%u %u %u %u %u %u),%d,%u,%llu,%llu,%llu,%u\n",
                rqd->id, ch, lun_id, inf_wr_addr.g.pl, inf_wr_addr.g.blk,
                inf_wr_addr.g.pg, inf_wr_addr.g.sec, coef_chnl, coef_wr, rd_remt,
                wr_remt, er_remt, plat);
    }

    return plat;
}
#endif

/*
 * Coperd: judge whether to return EBUSY for this request according to current
 * perlun inflight I/Os info
 *
 * NON-ZERO return value means we want to return EBUSY
 */
static int tos_busy(struct pblk *pblk, struct nvm_rq *rqd)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    int nr_luns = geo->nr_luns;
    struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
    unsigned long *lun_bitmap = r_ctx->lun_bitmap;
    struct pblk_lun *tlun;
    int bit = -1;
    //u64 lat;

    /* Coperd: only apply EBUSY for user data reads when tos_switch is on */
    if (!pblk->tos_switch || !rqd->bio->hflag || rqd->type != PBLK_IOTYPE_USER)
        return 0;

    while ((bit = find_next_bit(lun_bitmap, nr_luns, bit + 1)) < nr_luns) {
        tlun = &pblk->luns[bit];

#if 0
        lat = lat_predict_perlun(pblk, tlun, rqd);
        tlun->plat_us = lat;
        pr_debug("Coperd,predict,%d,%llu\n", rqd->id, lat);

        if (lat > rqd->plat_us)
            rqd->plat_us = lat;
#endif

        if (rqd->plat_us >= pblk->tos_tgt_lat) {
            rqd->ebusy = 1;
            atomic_inc(&pblk->nr_tt_busy);
            if (pblk->tos_switch == 1)
                return -EBUSY;
            else
                /* Coperd: faking ebusy mode, ebusy counting only */
                break;
        }
    }

    return 0;
}

int pblk_submit_io(struct pblk *pblk, struct nvm_rq *rqd)
{
    struct nvm_tgt_dev *dev = pblk->dev;

#ifdef CONFIG_NVM_DEBUG
    struct ppa_addr *ppa_list;
    int i;

    ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
    if (pblk_boundary_checks(dev, ppa_list, rqd->nr_ppas)) {
        WARN_ON(1);
        return -EINVAL;
    }

    /* Coperd: record the start time of this request */
    rqd->stime = ktime_get();
    rqd->plat_us = 0;
    rqd->tlat_us = 0;
    atomic_inc(&pblk->tos_rqd_id);
    rqd->id = atomic_read(&pblk->tos_rqd_id);

    if (rqd->opcode == NVM_OP_PWRITE) {
        struct pblk_line *line;
        struct ppa_addr ppa;

        for (i = 0; i < rqd->nr_ppas; i++) {
            ppa = ppa_list[i];
            line = &pblk->lines[pblk_ppa_to_line(ppa)];

            spin_lock(&line->lock);
            if (line->state != PBLK_LINESTATE_OPEN) {
                pr_err("pblk: bad ppa: line:%d,state:%d\n",
                        line->id, line->state);
                WARN_ON(1);
                spin_unlock(&line->lock);
                return -EINVAL;
            }
            spin_unlock(&line->lock);
        }

        up_perlun_inf_wr(pblk, rqd);

    } else if (rqd->opcode == NVM_OP_PREAD) {

#if 0
        if (pblk->tos_pr_lat == TOS_PR_RDONLY || pblk->tos_pr_lat == TOS_PR_ALL) {
            pr_debug("Coperd,rqd-s,%d,%x,%llu\n", rqd->id, rqd->opcode,
                    ktime_to_us(rqd->stime));
        }
#endif

        up_perlun_inf_rd(pblk, rqd);

        if (tos_busy(pblk, rqd)) {
            rqd->error = -EBUSY;
            return -EBUSY;
        }

    } else if (rqd->opcode == NVM_OP_ERASE) {

        up_perlun_inf_er(pblk, rqd);

    }
#endif

    return nvm_submit_io(dev, rqd);
}

struct bio *pblk_bio_map_addr(struct pblk *pblk, void *data,
			      unsigned int nr_secs, unsigned int len,
			      gfp_t gfp_mask)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	void *kaddr = data;
	struct page *page;
	struct bio *bio;
	int i, ret;

	if (l_mg->emeta_alloc_type == PBLK_KMALLOC_META)
		return bio_map_kern(dev->q, kaddr, len, gfp_mask);

	bio = bio_kmalloc(gfp_mask, nr_secs);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < nr_secs; i++) {
		page = vmalloc_to_page(kaddr);
		if (!page) {
			pr_err("pblk: could not map vmalloc emeta\n");
			bio_put(bio);
			bio = ERR_PTR(-ENOMEM);
			goto out;
		}

		ret = bio_add_pc_page(dev->q, bio, page, PAGE_SIZE, 0);
		if (ret != PAGE_SIZE) {
			pr_err("pblk: could not add page to emeta bio\n");
			bio_put(bio);
			bio = ERR_PTR(-ENOMEM);
			goto out;
		}

		kaddr += PAGE_SIZE;
	}

out:
	return bio;
}

int pblk_calc_secs(struct pblk *pblk, unsigned long secs_avail,
		    unsigned long secs_to_flush)
{
	int max = pblk->max_write_pgs;
	int min = pblk->min_write_pgs;
	int secs_to_sync = 0;

	if (secs_avail >= max)
		secs_to_sync = max;
	else if (secs_avail >= min)
		secs_to_sync = min * (secs_avail / min);
	else if (secs_to_flush)
		secs_to_sync = min;

	return secs_to_sync;
}

static u64 __pblk_alloc_page(struct pblk *pblk, struct pblk_line *line,
			     int nr_secs)
{
	u64 addr;
	int i;

	/* logic error: ppa out-of-bounds */
	BUG_ON(line->cur_sec + nr_secs > pblk->lm.sec_per_line);

	line->cur_sec = addr = find_next_zero_bit(line->map_bitmap,
					pblk->lm.sec_per_line, line->cur_sec);
	for (i = 0; i < nr_secs; i++, line->cur_sec++)
		WARN_ON(test_and_set_bit(line->cur_sec, line->map_bitmap));

	return addr;
}

u64 pblk_alloc_page(struct pblk *pblk, struct pblk_line *line, int nr_secs)
{
	u64 addr;

	/* Lock needed in case a write fails and a recovery needs to remap
	 * failed write buffer entries
	 */
	spin_lock(&line->lock);
	addr = __pblk_alloc_page(pblk, line, nr_secs);
	line->left_msecs -= nr_secs;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(line->left_msecs < 0);
#endif
	spin_unlock(&line->lock);

	return addr;
}

/*
 * Submit emeta to one LUN in the raid line at the time to avoid a deadlock when
 * taking the per LUN semaphore.
 */
static int pblk_line_submit_emeta_io(struct pblk *pblk, struct pblk_line *line,
				     u64 paddr, int dir)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    struct pblk_line_meta *lm = &pblk->lm;
    struct bio *bio;
    struct nvm_rq rqd;
    struct ppa_addr *ppa_list;
    dma_addr_t dma_ppa_list;
    void *emeta = line->emeta;
    int min = pblk->min_write_pgs;
    int left_ppas = lm->emeta_sec;
    int id = line->id;
    int rq_ppas, rq_len;
    int cmd_op, bio_op;
    int flags;
    int i, j;
    int ret;
    DECLARE_COMPLETION_ONSTACK(wait);

    if (dir == WRITE) {
        bio_op = REQ_OP_WRITE;
        cmd_op = NVM_OP_PWRITE;
        flags = pblk_set_progr_mode(pblk, WRITE);
    } else if (dir == READ) {
        bio_op = REQ_OP_READ;
        cmd_op = NVM_OP_PREAD;
        flags = pblk_set_read_mode(pblk);
    } else
        return -EINVAL;

    ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_ppa_list);
    if (!ppa_list)
        return -ENOMEM;

next_rq:
    memset(&rqd, 0, sizeof(struct nvm_rq));

    rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
    rq_len = rq_ppas * geo->sec_size;

    bio = pblk_bio_map_addr(pblk, emeta, rq_ppas, rq_len, GFP_KERNEL);
    if (IS_ERR(bio)) {
        ret = PTR_ERR(bio);
        goto free_rqd_dma;
    }

    bio->bi_iter.bi_sector = 0; /* artificial bio */
    bio_set_op_attrs(bio, bio_op, 0);
    bio->bi_private = &wait;
    bio->bi_end_io = pblk_end_bio_sync;

    rqd.bio = bio;
    rqd.opcode = cmd_op;
    rqd.flags = flags;
    rqd.nr_ppas = rq_ppas;
    rqd.ppa_list = ppa_list;
    rqd.dma_ppa_list = dma_ppa_list;
    rqd.type = PBLK_IOTYPE_META;

    if (dir == WRITE) {
        for (i = 0; i < rqd.nr_ppas; ) {
            paddr = __pblk_alloc_page(pblk, line, min);
            for (j = 0; j < min; j++, i++, paddr++)
                rqd.ppa_list[i] =
                    addr_to_gen_ppa(pblk, paddr, id);
        }
    } else {
        for (i = 0; i < rqd.nr_ppas; ) {
            struct ppa_addr ppa = addr_to_gen_ppa(pblk, paddr, id);
            int pos = pblk_ppa_to_pos(geo, ppa);

            while (test_bit(pos, line->blk_bitmap)) {
                paddr += min;
                ppa = addr_to_gen_ppa(pblk, paddr, id);
                pos = pblk_ppa_to_pos(geo, ppa);
            }

            for (j = 0; j < min; j++, i++, paddr++)
                rqd.ppa_list[i] =
                    addr_to_gen_ppa(pblk, paddr, line->id);
        }
    }

    ret = pblk_submit_io(pblk, &rqd);
    if (ret) {
        pr_err("pblk: emeta I/O submission failed: %d\n", ret);
        bio_put(bio);
        goto free_rqd_dma;
    }
    wait_for_completion_io(&wait);
    reinit_completion(&wait);

    if (dir == WRITE)
        down_perlun_inf_wr(pblk, &rqd);

    if (rqd.error) {
        if (dir == WRITE)
            pblk_log_write_err(pblk, &rqd);
        else
            pblk_log_read_err(pblk, &rqd);
    }
#ifdef CONFIG_NVM_DEBUG
    else
        BUG_ON(rqd.bio->bi_error);
#endif

    bio_put(bio);

    emeta += rq_len;
    left_ppas -= rq_ppas;
    if (left_ppas)
        goto next_rq;
free_rqd_dma:
    nvm_dev_dma_free(dev->parent, ppa_list, dma_ppa_list);
    return ret;
}

static int pblk_line_submit_smeta_io(struct pblk *pblk, struct pblk_line *line,
				     u64 paddr, int dir)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct pblk_line_meta *lm = &pblk->lm;
    struct bio *bio;
    struct nvm_rq rqd;
    u64 *lba_list = NULL;
    int i, ret;
    int cmd_op, bio_op;
    int flags;
    DECLARE_COMPLETION_ONSTACK(wait);

    if (dir == WRITE) {
        bio_op = REQ_OP_WRITE;
        cmd_op = NVM_OP_PWRITE;
        flags = pblk_set_progr_mode(pblk, WRITE);
        lba_list = pblk_line_emeta_to_lbas(line->emeta);
    } else if (dir == READ) {
        bio_op = REQ_OP_READ;
        cmd_op = NVM_OP_PREAD;
        flags = pblk_set_read_mode(pblk);
    } else
        return -EINVAL;

    memset(&rqd, 0, sizeof(struct nvm_rq));

    rqd.ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
            &rqd.dma_ppa_list);
    if (!rqd.ppa_list)
        return -ENOMEM;

    bio = bio_map_kern(dev->q, line->smeta, lm->smeta_len, GFP_KERNEL);
    if (IS_ERR(bio)) {
        ret = PTR_ERR(bio);
        goto free_ppa_list;
    }

    bio->bi_iter.bi_sector = 0; /* artificial bio */
    bio_set_op_attrs(bio, bio_op, 0);
    bio->bi_private = &wait;
    bio->bi_end_io = pblk_end_bio_sync;

    rqd.bio = bio;
    rqd.opcode = cmd_op;
    rqd.flags = flags;
    rqd.nr_ppas = lm->smeta_sec;
    rqd.type = PBLK_IOTYPE_META;

    for (i = 0; i < lm->smeta_sec; i++, paddr++) {
        rqd.ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);
        if (dir == WRITE)
            lba_list[paddr] = ADDR_EMPTY;
    }

    ret = pblk_submit_io(pblk, &rqd);
    if (ret) {
        pr_err("pblk: smeta I/O submission failed: %d\n", ret);
        bio_put(bio);
        goto free_bio;
    }
    wait_for_completion_io(&wait);

    if (dir == WRITE)
        down_perlun_inf_wr(pblk, &rqd);

    if (rqd.error) {
        if (dir == WRITE)
            pblk_log_write_err(pblk, &rqd);
        else
            pblk_log_read_err(pblk, &rqd);
    }
#ifdef CONFIG_NVM_DEBUG
    else
        BUG_ON(rqd.bio->bi_error);
#endif

free_bio:
    bio_put(bio);
free_ppa_list:
    nvm_dev_dma_free(dev->parent, rqd.ppa_list, rqd.dma_ppa_list);

    return ret;
}

int pblk_line_read_smeta(struct pblk *pblk, struct pblk_line *line)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	u64 bpaddr;
	int bit;

	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	if (unlikely(bit >= lm->blk_per_line)) {
		pr_err("pblk: corrupted line %d\n", line->id);
		return -EFAULT;
	}

	bpaddr = bit * geo->sec_per_blk;

	return pblk_line_submit_smeta_io(pblk, line, bpaddr, READ);
}

int pblk_line_read_emeta(struct pblk *pblk, struct pblk_line *line)
{
	return pblk_line_submit_emeta_io(pblk, line, line->emeta_ssec, READ);
}

static int pblk_alloc_e_rq(struct pblk *pblk, struct nvm_rq *rqd,
			   struct ppa_addr ppa)
{
	rqd->opcode = NVM_OP_ERASE;
	rqd->ppa_addr = ppa;
	rqd->nr_ppas = 1;
	rqd->flags = pblk_set_progr_mode(pblk, ERASE);
	rqd->bio = NULL;

	return 0;
}

static int pblk_blk_erase_sync(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_rq rqd;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	memset(&rqd, 0, sizeof(struct nvm_rq));

	if (pblk_alloc_e_rq(pblk, &rqd, ppa))
		return -ENOMEM;

	rqd.end_io = pblk_end_io_sync;
	rqd.private = &wait;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	ret = pblk_submit_io(pblk, &rqd);
	if (ret) {
		struct nvm_tgt_dev *dev = pblk->dev;
		struct nvm_geo *geo = &dev->geo;

		pr_err("pblk: could not sync erase line:%llu,blk:%llu\n",
			pblk_ppa_to_line(ppa), pblk_ppa_to_pos(geo, ppa));

		rqd.error = ret;
		goto out;
	}
	wait_for_completion_io(&wait);

out:
	rqd.private = pblk;
	__pblk_end_io_erase(pblk, &rqd);

	return 0;
}

static int pblk_line_erase(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct ppa_addr ppa;
	int bit = -1;

	/* Erase one block at the time and only erase good blocks */
	while ((bit = find_next_zero_bit(line->erase_bitmap, lm->blk_per_line,
						bit + 1)) < lm->blk_per_line) {
		ppa = pblk->luns[bit].bppa; /* set ch and lun */
		ppa.g.blk = line->id;

		/* If the erase fails, the block is bad and should be marked */
		line->left_eblks--;
		WARN_ON(test_and_set_bit(bit, line->erase_bitmap));

		if (pblk_blk_erase_sync(pblk, ppa))
			return -ENOMEM;
	}

	return 0;
}

/* For now lines are always assumed full lines. Thus, smeta former and current
 * lun bitmaps are omitted.
 */
static int pblk_line_setup(struct pblk *pblk, struct pblk_line *line,
			   struct pblk_line *cur, int line_type)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct line_smeta *smeta = line->smeta;
	struct line_emeta *emeta = line->emeta;
	u32 crc = ~(u32)0;
	int nr_bb = 0;
	int slun;
	u64 off;
	int bit;

	/* After erasing the line, we risk having an invalid line */
	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	if (unlikely(bit >= lm->blk_per_line)) {
		spin_lock(&l_mg->free_lock);
		spin_lock(&line->lock);
		line->state = PBLK_LINESTATE_BAD;
		spin_unlock(&line->lock);

		list_add_tail(&line->list, &l_mg->bad_list);
		spin_unlock(&l_mg->free_lock);

		pr_debug("pblk: line %d is bad\n", line->id);
		return 0;
	}

	line->type = line_type;

	/* Run-time metadata */
	line->lun_bitmap = ((void *)(smeta)) + sizeof(struct line_smeta);

	/* Mark LUNs allocated in this line (all for now) */
	line->sec_in_line = lm->sec_per_line;
	bitmap_set(line->lun_bitmap, 0, lm->lun_bitmap_len);
	slun = find_first_bit(line->lun_bitmap, lm->lun_bitmap_len);

	/* Start metadata */
	smeta->nr_luns = geo->nr_luns;
	smeta->line_type = line->type;
	smeta->id = line->id;
	smeta->slun = slun;
	smeta->seq_nr = line->seq_nr;
	smeta->smeta_len = lm->smeta_len;

	/* Fill metadata among lines */
	if (likely(cur)) {
		memcpy(line->lun_bitmap, cur->lun_bitmap, lm->lun_bitmap_len);
		smeta->p_id = cur->id;
		smeta->p_slun =
			find_first_bit(cur->lun_bitmap, lm->lun_bitmap_len);
		cur->emeta->n_id = line->id;
		cur->emeta->n_slun =
			find_first_bit(line->lun_bitmap, lm->lun_bitmap_len);
	} else {
		smeta->p_id = PBLK_LINE_EMPTY;
		smeta->p_slun = PBLK_LINE_EMPTY;
	}

	crc = crc32_le(crc, (unsigned char *)smeta + sizeof(crc),
					lm->smeta_len - sizeof(crc));
	smeta->crc = crc;

	/* End metadata */
	emeta->nr_luns = geo->nr_luns;
	emeta->line_type = line->type;
	emeta->id = line->id;
	emeta->slun = slun;
	emeta->seq_nr = line->seq_nr;
	emeta->nr_lbas = lm->sec_per_line - lm->emeta_sec - lm->smeta_sec;
	emeta->n_id = PBLK_LINE_EMPTY;
	emeta->n_slun = PBLK_LINE_EMPTY;
	emeta->emeta_len = lm->emeta_len;
	emeta->crc = 0;

	/* Capture bad block information on line mapping bitmaps */
	bit = -1;
	while ((bit = find_next_bit(line->blk_bitmap, lm->blk_per_line,
					bit + 1)) < lm->blk_per_line) {
		off = bit * geo->sec_per_pl;
		bitmap_shift_left(l_mg->bb_aux, l_mg->bb_template, off,
							lm->sec_per_line);
		bitmap_or(line->map_bitmap, line->map_bitmap, l_mg->bb_aux,
							lm->sec_per_line);
		line->sec_in_line -= geo->sec_per_blk;
		if (bit >= lm->emeta_bb)
			nr_bb++;
	}

	/* Mark smeta metadata sectors as bad sectors */
	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	off = bit * geo->sec_per_pl;
retry_smeta:
	bitmap_set(line->map_bitmap, off, lm->smeta_sec);
	line->sec_in_line -= lm->smeta_sec;
	line->smeta_ssec = off;
	line->cur_sec = off + lm->smeta_sec;

	bitmap_copy(line->invalid_bitmap, line->map_bitmap, lm->sec_per_line);

	if (pblk_line_submit_smeta_io(pblk, line, off, WRITE)) {
		pr_debug("pblk: line smeta I/O failed. Retry\n");
		off += geo->sec_per_pl;
		goto retry_smeta;
	}

	/* Mark emeta metadata sectors as bad sectors. We need to consider bad
	 * blocks to make sure that there are enough sectors to store emeta
	 */
	bit = lm->sec_per_line;
	off = lm->sec_per_line - lm->emeta_sec;
	bitmap_set(line->invalid_bitmap, off, lm->emeta_sec);
	while (nr_bb) {
		off -= geo->sec_per_pl;
		if (!test_bit(off, line->invalid_bitmap)) {
			bitmap_set(line->invalid_bitmap, off, geo->sec_per_pl);
			nr_bb--;
		}
	}

	line->sec_in_line -= lm->emeta_sec;
	line->emeta_ssec = off;
	line->vsc = line->left_ssecs = line->left_msecs = line->sec_in_line;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(lm->sec_per_line - line->sec_in_line !=
		bitmap_weight(line->invalid_bitmap, lm->sec_per_line));
#endif

	return 1;
}

struct pblk_line *pblk_line_get(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *line = NULL;
	int bit;

retry_get:
	if (list_empty(&l_mg->free_list)) {
		pr_err("pblk: no free lines\n");
		goto out;
	}

	line = list_first_entry(&l_mg->free_list, struct pblk_line, list);
	list_del(&line->list);

	/* Bad blocks do not need to be erased */
	bitmap_copy(line->erase_bitmap, line->blk_bitmap, lm->blk_per_line);
	line->left_eblks = line->blk_in_line;
	atomic_set(&line->left_seblks, line->left_eblks);

	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	if (unlikely(bit >= lm->blk_per_line)) {
		spin_lock(&l_mg->free_lock);
		spin_lock(&line->lock);
		line->state = PBLK_LINESTATE_BAD;
		spin_unlock(&line->lock);

		list_add_tail(&line->list, &l_mg->bad_list);
		spin_unlock(&l_mg->free_lock);

		pr_err("pblk: line %d is bad\n", line->id);
		goto retry_get;
	}

	spin_lock(&line->lock);
	BUG_ON(line->state != PBLK_LINESTATE_FREE);
	line->state = PBLK_LINESTATE_OPEN;
	spin_unlock(&line->lock);

	kref_init(&line->ref);

out:
	return line;
}

struct pblk_line *pblk_line_get_first_data(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *line;
	unsigned long *b, *p;
	int meta_line;

	b = mempool_alloc(pblk->line_meta_pool, GFP_KERNEL);
	if (!b)
		return NULL;
	memset(b, 0, lm->sec_bitmap_len);

	p = mempool_alloc(pblk->line_meta_pool, GFP_KERNEL);
	if (!p)
		goto fail_free_meta_bitmap;

	spin_lock(&l_mg->free_lock);
	line = pblk_line_get(pblk);
	if (!line) {
		spin_unlock(&l_mg->free_lock);
		goto fail_free_invalid_bitmap;
	}

	line->map_bitmap = b;
	line->invalid_bitmap = p;

	line->seq_nr = l_mg->d_seq_nr++;
	l_mg->data_line = line;
	l_mg->nr_free_lines--;

	meta_line = find_first_zero_bit(&l_mg->meta_bitmap, PBLK_DATA_LINES);
	set_bit(meta_line, &l_mg->meta_bitmap);
	line->smeta = l_mg->sline_meta[meta_line].meta;
	line->emeta = l_mg->eline_meta[meta_line].meta;
	line->meta_line = meta_line;
	spin_unlock(&l_mg->free_lock);

	if (pblk_line_erase(pblk, line))
		goto fail_free_invalid_bitmap;

	pblk_rl_free_lines_dec(&pblk->rl, line);

retry_setup:
	if (!pblk_line_setup(pblk, line, NULL, PBLK_LINETYPE_DATA)) {
		struct pblk_line *retry_line;

		spin_lock(&l_mg->free_lock);
		retry_line = pblk_line_get(pblk);

		retry_line->smeta = line->smeta;
		retry_line->emeta = line->emeta;
		retry_line->meta_line = line->meta_line;
		retry_line->map_bitmap = b;
		retry_line->invalid_bitmap = p;

		line->map_bitmap = NULL;
		line->invalid_bitmap = NULL;
		line->smeta = NULL;
		line->emeta = NULL;
		spin_unlock(&l_mg->free_lock);

		if (pblk_line_erase(pblk, retry_line))
			pr_debug("pblk: only one data line available\n");

		pblk_rl_free_lines_dec(&pblk->rl, retry_line);

		l_mg->data_line = retry_line;
		line = retry_line;
		goto retry_setup;
	}

	return line;

fail_free_invalid_bitmap:
	mempool_free(p, pblk->line_meta_pool);
fail_free_meta_bitmap:
	mempool_free(b, pblk->line_meta_pool);

	return NULL;
}

static struct pblk_line *__pblk_line_get_next_data(struct pblk *pblk,
						   struct pblk_line_mgmt *l_mg,
						   unsigned long *b,
						   unsigned long *p)
{
	struct pblk_line *line;

	line = pblk_line_get(pblk);
	if (!line) {
		l_mg->data_next = NULL;
		return NULL;
	}

	line->map_bitmap = b;
	line->invalid_bitmap = p;

	line->seq_nr = l_mg->d_seq_nr++;
	l_mg->data_next = line;
	l_mg->nr_free_lines--;

	return line;
}

struct pblk_line *pblk_line_get_next_data(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *line;
	unsigned long *b, *p;

	b = mempool_alloc(pblk->line_meta_pool, GFP_KERNEL);
	if (!b)
		return NULL;
	memset(b, 0, lm->sec_bitmap_len);

	p = mempool_alloc(pblk->line_meta_pool, GFP_KERNEL);
	if (!p) {
		mempool_free(b, pblk->line_meta_pool);
		return NULL;
	}

	spin_lock(&l_mg->free_lock);
	line = __pblk_line_get_next_data(pblk, l_mg, b, p);
	spin_unlock(&l_mg->free_lock);

	return line;
}

struct pblk_line *pblk_line_replace_data(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *cur, *new;
	unsigned long *b, *p;
	unsigned int left_seblks;
	int meta_line;

	b = mempool_alloc(pblk->line_meta_pool, GFP_KERNEL);
	if (!b)
		return NULL;
	memset(b, 0, lm->sec_bitmap_len);

	p = mempool_alloc(pblk->line_meta_pool, GFP_KERNEL);
	if (!p) {
		mempool_free(b, pblk->line_meta_pool);
		return NULL;
	}

	cur = l_mg->data_line;
	new = l_mg->data_next;
	if (!new)
		return NULL;
	l_mg->data_line = new;

retry_line:
	left_seblks = atomic_read(&new->left_seblks);
	if (left_seblks) {
		/* If line is not fully erased, erase it */
		if (new->left_eblks) {
			if (pblk_line_erase(pblk, new))
				return NULL;
		} else {
			io_schedule();
		}
		goto retry_line;
	}

	spin_lock(&l_mg->free_lock);
#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!bitmap_full(new->erase_bitmap, lm->blk_per_line));
#endif

	l_mg->data_next = __pblk_line_get_next_data(pblk, l_mg, b, p);
	if (!l_mg->data_next)
		pr_debug("pblk: using last line\n");

retry_meta:
	meta_line = find_first_zero_bit(&l_mg->meta_bitmap, PBLK_DATA_LINES);
	if (meta_line == PBLK_DATA_LINES) {
		spin_unlock(&l_mg->free_lock);
		schedule();
		spin_lock(&l_mg->free_lock);
		goto retry_meta;
	}

	set_bit(meta_line, &l_mg->meta_bitmap);
	new->smeta = l_mg->sline_meta[meta_line].meta;
	new->emeta = l_mg->eline_meta[meta_line].meta;
	new->meta_line = meta_line;

	memset(new->smeta, 0, lm->smeta_len);
	memset(new->emeta, 0, lm->emeta_len);
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_dec(&pblk->rl, new);

retry_setup:
	if (!pblk_line_setup(pblk, new, cur, PBLK_LINETYPE_DATA)) {
		struct pblk_line *retry_line;

		spin_lock(&l_mg->free_lock);
		retry_line = pblk_line_get(pblk);

		retry_line->smeta = new->smeta;
		retry_line->emeta = new->emeta;
		retry_line->meta_line = new->meta_line;
		retry_line->map_bitmap = new->map_bitmap;
		retry_line->invalid_bitmap = new->invalid_bitmap;

		new->map_bitmap = NULL;
		new->invalid_bitmap = NULL;
		new->smeta = NULL;
		new->emeta = NULL;
		spin_unlock(&l_mg->free_lock);

		pblk_rl_free_lines_dec(&pblk->rl, retry_line);
		if (pblk_line_erase(pblk, retry_line))
			pr_debug("pblk: allocating last line\n");

		l_mg->data_line = retry_line;
		new = retry_line;
		goto retry_setup;
	}

	return new;
}

void pblk_line_put(struct kref *ref)
{
	struct pblk_line *line = container_of(ref, struct pblk_line, ref);
	struct pblk *pblk = line->pblk;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	spin_lock(&line->lock);
	BUG_ON(line->state != PBLK_LINESTATE_GC);
	line->state = PBLK_LINESTATE_FREE;
	line->gc_group = PBLK_LINEGC_NONE;
	pblk_line_free(pblk, line);
	spin_unlock(&line->lock);

	spin_lock(&l_mg->free_lock);
	list_add_tail(&line->list, &l_mg->free_list);
	l_mg->nr_free_lines++;
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_inc(&pblk->rl, line);
}

int pblk_blk_erase_async(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int err;

	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd)
		return -ENOMEM;

	memset(rqd, 0, pblk_r_rq_size);

	if (pblk_alloc_e_rq(pblk, rqd, ppa))
		return -ENOMEM;

	rqd->end_io = pblk_end_io_erase;
	rqd->private = pblk;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	err = pblk_submit_io(pblk, rqd);
	if (err) {
		struct nvm_tgt_dev *dev = pblk->dev;
		struct nvm_geo *geo = &dev->geo;

		pr_err("pblk: could not async erase line:%llu,blk:%llu\n",
			pblk_ppa_to_line(ppa), pblk_ppa_to_pos(geo, ppa));
	}

	return 0;
}

struct pblk_line *pblk_line_get_data(struct pblk *pblk)
{
	return pblk->l_mg.data_line;
}

struct pblk_line *pblk_line_get_data_next(struct pblk *pblk)
{
	return pblk->l_mg.data_next;
}

int pblk_line_is_full(struct pblk_line *line)
{
	return (line->left_msecs == 0);
}

void pblk_line_free(struct pblk *pblk, struct pblk_line *line)
{
	if (line->map_bitmap)
		mempool_free(line->map_bitmap, pblk->line_meta_pool);
	if (line->invalid_bitmap)
		mempool_free(line->invalid_bitmap, pblk->line_meta_pool);

	line->map_bitmap = NULL;
	line->invalid_bitmap = NULL;
}

void pblk_line_close(struct work_struct *work)
{
	struct pblk_line_ws *line_ws = container_of(work, struct pblk_line_ws,
									ws);
	struct pblk *pblk = line_ws->pblk;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line = line_ws->priv;
	struct list_head *move_list;
	u32 crc = ~(u32)0;

	crc = crc32_le(crc, (unsigned char *)line->emeta + sizeof(crc),
					lm->emeta_len - sizeof(crc));
	line->emeta->crc = cpu_to_le32(crc);

	if (pblk_line_submit_emeta_io(pblk, line, line->cur_sec, WRITE))
		pr_err("pblk: line %d close I/O failed\n", line->id);

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!bitmap_full(line->map_bitmap, line->sec_in_line));
#endif

	spin_lock(&l_mg->free_lock);
	WARN_ON(!test_and_clear_bit(line->meta_line, &l_mg->meta_bitmap));
	spin_unlock(&l_mg->free_lock);

	spin_lock(&line->lock);
	WARN_ON(line->state != PBLK_LINESTATE_OPEN);
	line->state = PBLK_LINESTATE_CLOSED;
	move_list = pblk_line_gc_list(pblk, line);
	BUG_ON(!move_list);
	spin_unlock(&line->lock);

	spin_lock(&l_mg->gc_lock);
	list_add_tail(&line->list, move_list);
	spin_unlock(&l_mg->gc_lock);

	mempool_free(line->map_bitmap, pblk->line_meta_pool);
	line->map_bitmap = NULL;
	line->smeta = NULL;
	line->emeta = NULL;

	mempool_free(line_ws, pblk->line_ws_pool);
}

void pblk_line_mark_bb(struct work_struct *work)
{
	struct pblk_line_ws *line_ws = container_of(work, struct pblk_line_ws,
									ws);
	struct pblk *pblk = line_ws->pblk;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct ppa_addr *ppa = line_ws->priv;
	int ret;

	ret = nvm_set_tgt_bb_tbl(dev, ppa, 1, NVM_BLK_T_GRWN_BAD);
	if (ret) {
		struct pblk_line *line;
		int pos;

		line = &pblk->lines[pblk_ppa_to_line(*ppa)];
		pos = pblk_ppa_to_pos(&dev->geo, *ppa);

		pr_err("pblk: failed to mark bb, line:%d, pos:%d\n",
				line->id, pos);
	}

	kfree(ppa);
	mempool_free(line_ws, pblk->line_ws_pool);
}

void pblk_line_run_ws(struct pblk *pblk, void *priv,
		      void (*work)(struct work_struct *))
{
	struct pblk_line_ws *line_ws;

	line_ws = mempool_alloc(pblk->line_ws_pool, GFP_ATOMIC);
	if (!line_ws)
		return;

	line_ws->pblk = pblk;
	line_ws->priv = priv;

	INIT_WORK(&line_ws->ws, work);
	queue_work(pblk->kw_wq, &line_ws->ws);
}

void pblk_down_rq(struct pblk *pblk, struct ppa_addr *ppa_list, int nr_ppas,
		  unsigned long *lun_bitmap)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	int lun_id = ppa_list[0].g.ch * geo->luns_per_chnl + ppa_list[0].g.lun;
	int ret;

	/*
	 * Only send one inflight I/O per LUN. Since we map at a page
	 * granurality, all ppas in the I/O will map to the same LUN
	 */
#ifdef CONFIG_NVM_DEBUG
	int i;

	for (i = 1; i < nr_ppas; i++)
		BUG_ON(ppa_list[0].g.lun != ppa_list[i].g.lun ||
				ppa_list[0].g.ch != ppa_list[i].g.ch);
#endif
	/* If the LUN has been locked for this same request, do no attempt to
	 * lock it again
	 */
	if (test_and_set_bit(lun_id, lun_bitmap))
		return;

	rlun = &pblk->luns[lun_id];
	ret = down_timeout(&rlun->wr_sem, msecs_to_jiffies(60000));
	if (ret) {
		switch (ret) {
		case -ETIME:
			pr_err("pblk: lun semaphore timed out\n");
			break;
		case -EINTR:
			pr_err("pblk: lun semaphore timed out\n");
			break;
		}
	}
}

void pblk_up_rq(struct pblk *pblk, struct ppa_addr *ppa_list, int nr_ppas,
		unsigned long *lun_bitmap)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	int nr_luns = geo->nr_luns;
	int bit = -1;

	while ((bit = find_next_bit(lun_bitmap, nr_luns, bit + 1)) < nr_luns) {
		rlun = &pblk->luns[bit];
		up(&rlun->wr_sem);
	}

	kfree(lun_bitmap);
}

void pblk_update_map_cache(struct pblk *pblk, sector_t lba,
			  struct ppa_addr ppa)
{
	struct ppa_addr *l2p_ppa;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!nvm_addr_in_cache(ppa));
	BUG_ON(pblk_rb_pos_oob(&pblk->rwb, nvm_addr_to_cacheline(ppa)));
#endif

	/* logic error: lba out-of-bounds */
	BUG_ON(lba >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	l2p_ppa = &pblk->trans_map[lba];

	if (!nvm_addr_in_cache(*l2p_ppa) && !ppa_empty(*l2p_ppa))
		pblk_page_invalidate(pblk, *l2p_ppa);

	*l2p_ppa = ppa;
	spin_unlock(&pblk->trans_lock);
}

void pblk_update_map_gc(struct pblk *pblk, sector_t lba, struct ppa_addr ppa,
		       struct pblk_line *gc_line)
{
	struct ppa_addr *l2p_ppa;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!nvm_addr_in_cache(ppa));
	BUG_ON(pblk_rb_pos_oob(&pblk->rwb, nvm_addr_to_cacheline(ppa)));
#endif

	/* logic error: lba out-of-bounds */
	WARN_ON(lba >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	l2p_ppa = &pblk->trans_map[lba];

	/* Prevent updated entries to be overwritten by GC */
	if (nvm_addr_in_cache(*l2p_ppa) || ppa_empty(*l2p_ppa) ||
				pblk_ppa_to_line(*l2p_ppa) != gc_line->id)
		goto out;

	*l2p_ppa = ppa;
out:
	spin_unlock(&pblk->trans_lock);
}

void pblk_update_map_dev(struct pblk *pblk, sector_t lba,
			struct ppa_addr ppa, struct ppa_addr entry_line)
{
	struct ppa_addr *l2p_line;

	/* logic error: lba out-of-bounds */
	BUG_ON(lba >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	l2p_line = &pblk->trans_map[lba];

	/* Do not update L2P if the cacheline has been updated. In this case,
	 * the mapped ppa must be einvalidated
	 */
	if (l2p_line->ppa != entry_line.ppa && !ppa_empty(ppa)) {
		pblk_page_invalidate(pblk, ppa);
		goto out;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nvm_addr_in_cache(ppa));
	BUG_ON(!nvm_addr_in_cache(*l2p_line) && !ppa_empty(*l2p_line));
#endif

	*l2p_line = ppa;
out:
	spin_unlock(&pblk->trans_lock);
}

void pblk_lookup_l2p_seq(struct pblk *pblk, struct ppa_addr *ppas,
			 sector_t blba, int nr_secs)
{
	int i;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++)
		ppas[i] = pblk->trans_map[blba + i];
	spin_unlock(&pblk->trans_lock);
}

void pblk_lookup_l2p_rand(struct pblk *pblk, struct ppa_addr *ppas,
			  u64 *lba_list, int nr_secs)
{
	sector_t lba;
	int i;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++) {
		lba = lba_list[i];
		if (lba == ADDR_EMPTY) {
			ppas[i].ppa = ADDR_EMPTY;
		} else {
			/* logic error: lba out-of-bounds */
			BUG_ON(!(lba >= 0 && lba < pblk->rl.nr_secs));
			ppas[i] = pblk->trans_map[lba];
		}
	}
	spin_unlock(&pblk->trans_lock);
}
