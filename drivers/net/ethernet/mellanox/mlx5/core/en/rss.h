/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. */

#ifndef __MLX5_EN_RSS_H__
#define __MLX5_EN_RSS_H__

#include "rqt.h"
#include "tir.h"
#include "fs.h"

enum mlx5e_rss_init_type {
	MLX5E_RSS_INIT_NO_TIRS = 0,
	MLX5E_RSS_INIT_TIRS
};

struct mlx5e_rss_params_traffic_type
mlx5e_rss_get_default_tt_config(enum mlx5_traffic_types tt);

struct mlx5e_rss;

int mlx5e_rss_params_indir_init(struct mlx5e_rss_params_indir *indir, struct mlx5_core_dev *mdev,
				u32 actual_table_size, u32 max_table_size);
void mlx5e_rss_params_indir_cleanup(struct mlx5e_rss_params_indir *indir);
void mlx5e_rss_params_indir_modify_actual_size(struct mlx5e_rss *rss, u32 num_channels);
struct mlx5e_rss *mlx5e_rss_init(struct mlx5_core_dev *mdev, bool inner_ft_support, u32 drop_rqn,
				 const struct mlx5e_packet_merge_param *init_pkt_merge_param,
				 enum mlx5e_rss_init_type type, unsigned int nch,
				 unsigned int max_nch);
int mlx5e_rss_cleanup(struct mlx5e_rss *rss);

void mlx5e_rss_refcnt_inc(struct mlx5e_rss *rss);
void mlx5e_rss_refcnt_dec(struct mlx5e_rss *rss);
unsigned int mlx5e_rss_refcnt_read(struct mlx5e_rss *rss);

bool mlx5e_rss_get_inner_ft_support(struct mlx5e_rss *rss);
u32 mlx5e_rss_get_tirn(struct mlx5e_rss *rss, enum mlx5_traffic_types tt,
		       bool inner);
bool mlx5e_rss_valid_tir(struct mlx5e_rss *rss, enum mlx5_traffic_types tt, bool inner);
u32 mlx5e_rss_get_rqtn(struct mlx5e_rss *rss);
int mlx5e_rss_obtain_tirn(struct mlx5e_rss *rss,
			  enum mlx5_traffic_types tt,
			  const struct mlx5e_packet_merge_param *init_pkt_merge_param,
			  bool inner, u32 *tirn);

void mlx5e_rss_enable(struct mlx5e_rss *rss, u32 *rqns, u32 *vhca_ids, unsigned int num_rqns);
void mlx5e_rss_disable(struct mlx5e_rss *rss);

int mlx5e_rss_packet_merge_set_param(struct mlx5e_rss *rss,
				     struct mlx5e_packet_merge_param *pkt_merge_param);
void mlx5e_rss_get_rxfh(struct mlx5e_rss *rss, u32 *indir, u8 *key, u8 *hfunc,
			bool *symmetric);
int mlx5e_rss_set_rxfh(struct mlx5e_rss *rss, const u32 *indir,
		       const u8 *key, const u8 *hfunc, const bool *symmetric,
		       u32 *rqns, u32 *vhca_ids, unsigned int num_rqns);
struct mlx5e_rss_params_hash mlx5e_rss_get_hash(struct mlx5e_rss *rss);
u8 mlx5e_rss_get_hash_fields(struct mlx5e_rss *rss, enum mlx5_traffic_types tt);
int mlx5e_rss_set_hash_fields(struct mlx5e_rss *rss, enum mlx5_traffic_types tt,
			      u8 rx_hash_fields);
void mlx5e_rss_set_indir_uniform(struct mlx5e_rss *rss, unsigned int nch);
#endif /* __MLX5_EN_RSS_H__ */
