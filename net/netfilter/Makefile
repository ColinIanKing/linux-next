# SPDX-License-Identifier: GPL-2.0
netfilter-objs := core.o nf_log.o nf_queue.o nf_sockopt.o utils.o

nf_conntrack-y	:= nf_conntrack_core.o nf_conntrack_standalone.o nf_conntrack_expect.o nf_conntrack_helper.o \
		   nf_conntrack_proto.o nf_conntrack_proto_generic.o nf_conntrack_proto_tcp.o nf_conntrack_proto_udp.o \
		   nf_conntrack_proto_icmp.o \
		   nf_conntrack_extend.o nf_conntrack_acct.o nf_conntrack_seqadj.o

nf_conntrack-$(subst m,y,$(CONFIG_IPV6)) += nf_conntrack_proto_icmpv6.o
nf_conntrack-$(CONFIG_NF_CONNTRACK_TIMEOUT) += nf_conntrack_timeout.o
nf_conntrack-$(CONFIG_NF_CONNTRACK_TIMESTAMP) += nf_conntrack_timestamp.o
nf_conntrack-$(CONFIG_NF_CONNTRACK_EVENTS) += nf_conntrack_ecache.o
nf_conntrack-$(CONFIG_NF_CONNTRACK_LABELS) += nf_conntrack_labels.o
nf_conntrack-$(CONFIG_NF_CONNTRACK_OVS) += nf_conntrack_ovs.o
nf_conntrack-$(CONFIG_NF_CT_PROTO_SCTP) += nf_conntrack_proto_sctp.o
nf_conntrack-$(CONFIG_NF_CT_PROTO_GRE) += nf_conntrack_proto_gre.o
ifeq ($(CONFIG_NF_CONNTRACK),m)
nf_conntrack-$(CONFIG_DEBUG_INFO_BTF_MODULES) += nf_conntrack_bpf.o
else ifeq ($(CONFIG_NF_CONNTRACK),y)
nf_conntrack-$(CONFIG_DEBUG_INFO_BTF) += nf_conntrack_bpf.o
endif

obj-$(CONFIG_NETFILTER) = netfilter.o
obj-$(CONFIG_NETFILTER_BPF_LINK) += nf_bpf_link.o

obj-$(CONFIG_NETFILTER_NETLINK) += nfnetlink.o
obj-$(CONFIG_NETFILTER_NETLINK_ACCT) += nfnetlink_acct.o
obj-$(CONFIG_NETFILTER_NETLINK_QUEUE) += nfnetlink_queue.o
obj-$(CONFIG_NETFILTER_NETLINK_LOG) += nfnetlink_log.o
obj-$(CONFIG_NETFILTER_NETLINK_OSF) += nfnetlink_osf.o
obj-$(CONFIG_NETFILTER_NETLINK_HOOK) += nfnetlink_hook.o

# connection tracking
obj-$(CONFIG_NF_CONNTRACK) += nf_conntrack.o

# netlink interface for nf_conntrack
obj-$(CONFIG_NF_CT_NETLINK) += nf_conntrack_netlink.o
obj-$(CONFIG_NF_CT_NETLINK_TIMEOUT) += nfnetlink_cttimeout.o
obj-$(CONFIG_NF_CT_NETLINK_HELPER) += nfnetlink_cthelper.o

# connection tracking helpers
nf_conntrack_h323-objs := nf_conntrack_h323_main.o nf_conntrack_h323_asn1.o

obj-$(CONFIG_NF_CONNTRACK_AMANDA) += nf_conntrack_amanda.o
obj-$(CONFIG_NF_CONNTRACK_FTP) += nf_conntrack_ftp.o
obj-$(CONFIG_NF_CONNTRACK_H323) += nf_conntrack_h323.o
obj-$(CONFIG_NF_CONNTRACK_IRC) += nf_conntrack_irc.o
obj-$(CONFIG_NF_CONNTRACK_BROADCAST) += nf_conntrack_broadcast.o
obj-$(CONFIG_NF_CONNTRACK_NETBIOS_NS) += nf_conntrack_netbios_ns.o
obj-$(CONFIG_NF_CONNTRACK_SNMP) += nf_conntrack_snmp.o
obj-$(CONFIG_NF_CONNTRACK_PPTP) += nf_conntrack_pptp.o
obj-$(CONFIG_NF_CONNTRACK_SANE) += nf_conntrack_sane.o
obj-$(CONFIG_NF_CONNTRACK_SIP) += nf_conntrack_sip.o
obj-$(CONFIG_NF_CONNTRACK_TFTP) += nf_conntrack_tftp.o

nf_nat-y	:= nf_nat_core.o nf_nat_proto.o nf_nat_helper.o

obj-$(CONFIG_NF_LOG_SYSLOG) += nf_log_syslog.o

obj-$(CONFIG_NF_NAT) += nf_nat.o
nf_nat-$(CONFIG_NF_NAT_REDIRECT) += nf_nat_redirect.o
nf_nat-$(CONFIG_NF_NAT_MASQUERADE) += nf_nat_masquerade.o
nf_nat-$(CONFIG_NF_NAT_OVS) += nf_nat_ovs.o

ifeq ($(CONFIG_NF_NAT),m)
nf_nat-$(CONFIG_DEBUG_INFO_BTF_MODULES) += nf_nat_bpf.o
else ifeq ($(CONFIG_NF_NAT),y)
nf_nat-$(CONFIG_DEBUG_INFO_BTF) += nf_nat_bpf.o
endif

# NAT helpers
obj-$(CONFIG_NF_NAT_AMANDA) += nf_nat_amanda.o
obj-$(CONFIG_NF_NAT_FTP) += nf_nat_ftp.o
obj-$(CONFIG_NF_NAT_IRC) += nf_nat_irc.o
obj-$(CONFIG_NF_NAT_SIP) += nf_nat_sip.o
obj-$(CONFIG_NF_NAT_TFTP) += nf_nat_tftp.o

# SYNPROXY
obj-$(CONFIG_NETFILTER_SYNPROXY) += nf_synproxy_core.o

obj-$(CONFIG_NETFILTER_CONNCOUNT) += nf_conncount.o

# generic packet duplication from netdev family
obj-$(CONFIG_NF_DUP_NETDEV)	+= nf_dup_netdev.o

# nf_tables
nf_tables-objs := nf_tables_core.o nf_tables_api.o nft_chain_filter.o \
		  nf_tables_trace.o nft_immediate.o nft_cmp.o nft_range.o \
		  nft_bitwise.o nft_byteorder.o nft_payload.o nft_lookup.o \
		  nft_dynset.o nft_meta.o nft_rt.o nft_exthdr.o nft_last.o \
		  nft_counter.o nft_objref.o nft_inner.o \
		  nft_chain_route.o nf_tables_offload.o \
		  nft_set_hash.o nft_set_bitmap.o nft_set_rbtree.o \
		  nft_set_pipapo.o

ifdef CONFIG_X86_64
ifndef CONFIG_UML
nf_tables-objs += nft_set_pipapo_avx2.o
endif
endif

ifdef CONFIG_NFT_CT
ifdef CONFIG_MITIGATION_RETPOLINE
nf_tables-objs += nft_ct_fast.o
endif
endif

obj-$(CONFIG_NF_TABLES)		+= nf_tables.o
obj-$(CONFIG_NFT_COMPAT)	+= nft_compat.o
obj-$(CONFIG_NFT_CONNLIMIT)	+= nft_connlimit.o
obj-$(CONFIG_NFT_NUMGEN)	+= nft_numgen.o
obj-$(CONFIG_NFT_CT)		+= nft_ct.o
obj-$(CONFIG_NFT_FLOW_OFFLOAD)	+= nft_flow_offload.o
obj-$(CONFIG_NFT_LIMIT)		+= nft_limit.o
obj-$(CONFIG_NFT_NAT)		+= nft_nat.o
obj-$(CONFIG_NFT_QUEUE)		+= nft_queue.o
obj-$(CONFIG_NFT_QUOTA)		+= nft_quota.o
obj-$(CONFIG_NFT_REJECT) 	+= nft_reject.o
obj-$(CONFIG_NFT_REJECT_INET)	+= nft_reject_inet.o
obj-$(CONFIG_NFT_REJECT_NETDEV)	+= nft_reject_netdev.o
obj-$(CONFIG_NFT_TUNNEL)	+= nft_tunnel.o
obj-$(CONFIG_NFT_LOG)		+= nft_log.o
obj-$(CONFIG_NFT_MASQ)		+= nft_masq.o
obj-$(CONFIG_NFT_REDIR)		+= nft_redir.o
obj-$(CONFIG_NFT_HASH)		+= nft_hash.o
obj-$(CONFIG_NFT_FIB)		+= nft_fib.o
obj-$(CONFIG_NFT_FIB_INET)	+= nft_fib_inet.o
obj-$(CONFIG_NFT_FIB_NETDEV)	+= nft_fib_netdev.o
obj-$(CONFIG_NFT_SOCKET)	+= nft_socket.o
obj-$(CONFIG_NFT_OSF)		+= nft_osf.o
obj-$(CONFIG_NFT_TPROXY)	+= nft_tproxy.o
obj-$(CONFIG_NFT_XFRM)		+= nft_xfrm.o
obj-$(CONFIG_NFT_SYNPROXY)	+= nft_synproxy.o

obj-$(CONFIG_NFT_NAT)		+= nft_chain_nat.o

# nf_tables netdev
obj-$(CONFIG_NFT_DUP_NETDEV)	+= nft_dup_netdev.o
obj-$(CONFIG_NFT_FWD_NETDEV)	+= nft_fwd_netdev.o

# flow table infrastructure
obj-$(CONFIG_NF_FLOW_TABLE)	+= nf_flow_table.o
nf_flow_table-objs		:= nf_flow_table_core.o nf_flow_table_ip.o \
				   nf_flow_table_offload.o nf_flow_table_xdp.o
nf_flow_table-$(CONFIG_NF_FLOW_TABLE_PROCFS) += nf_flow_table_procfs.o
ifeq ($(CONFIG_NF_FLOW_TABLE),m)
nf_flow_table-$(CONFIG_DEBUG_INFO_BTF_MODULES) += nf_flow_table_bpf.o
else ifeq ($(CONFIG_NF_FLOW_TABLE),y)
nf_flow_table-$(CONFIG_DEBUG_INFO_BTF) += nf_flow_table_bpf.o
endif

obj-$(CONFIG_NF_FLOW_TABLE_INET) += nf_flow_table_inet.o

# generic X tables
obj-$(CONFIG_NETFILTER_XTABLES) += x_tables.o xt_tcpudp.o

# combos
obj-$(CONFIG_NETFILTER_XT_MARK) += xt_mark.o
obj-$(CONFIG_NETFILTER_XT_CONNMARK) += xt_connmark.o
obj-$(CONFIG_NETFILTER_XT_SET) += xt_set.o
obj-$(CONFIG_NETFILTER_XT_NAT) += xt_nat.o

# targets
obj-$(CONFIG_NETFILTER_XT_TARGET_AUDIT) += xt_AUDIT.o
obj-$(CONFIG_NETFILTER_XT_TARGET_CHECKSUM) += xt_CHECKSUM.o
obj-$(CONFIG_NETFILTER_XT_TARGET_CLASSIFY) += xt_CLASSIFY.o
obj-$(CONFIG_NETFILTER_XT_TARGET_CONNSECMARK) += xt_CONNSECMARK.o
obj-$(CONFIG_NETFILTER_XT_TARGET_CT) += xt_CT.o
obj-$(CONFIG_NETFILTER_XT_TARGET_DSCP) += xt_DSCP.o
obj-$(CONFIG_NETFILTER_XT_TARGET_HL) += xt_HL.o
obj-$(CONFIG_NETFILTER_XT_TARGET_HMARK) += xt_HMARK.o
obj-$(CONFIG_NETFILTER_XT_TARGET_LED) += xt_LED.o
obj-$(CONFIG_NETFILTER_XT_TARGET_LOG) += xt_LOG.o
obj-$(CONFIG_NETFILTER_XT_TARGET_NETMAP) += xt_NETMAP.o
obj-$(CONFIG_NETFILTER_XT_TARGET_NFLOG) += xt_NFLOG.o
obj-$(CONFIG_NETFILTER_XT_TARGET_NFQUEUE) += xt_NFQUEUE.o
obj-$(CONFIG_NETFILTER_XT_TARGET_RATEEST) += xt_RATEEST.o
obj-$(CONFIG_NETFILTER_XT_TARGET_REDIRECT) += xt_REDIRECT.o
obj-$(CONFIG_NETFILTER_XT_TARGET_MASQUERADE) += xt_MASQUERADE.o
obj-$(CONFIG_NETFILTER_XT_TARGET_SECMARK) += xt_SECMARK.o
obj-$(CONFIG_NETFILTER_XT_TARGET_TPROXY) += xt_TPROXY.o
obj-$(CONFIG_NETFILTER_XT_TARGET_TCPMSS) += xt_TCPMSS.o
obj-$(CONFIG_NETFILTER_XT_TARGET_TCPOPTSTRIP) += xt_TCPOPTSTRIP.o
obj-$(CONFIG_NETFILTER_XT_TARGET_TEE) += xt_TEE.o
obj-$(CONFIG_NETFILTER_XT_TARGET_TRACE) += xt_TRACE.o
obj-$(CONFIG_NETFILTER_XT_TARGET_IDLETIMER) += xt_IDLETIMER.o

# matches
obj-$(CONFIG_NETFILTER_XT_MATCH_ADDRTYPE) += xt_addrtype.o
obj-$(CONFIG_NETFILTER_XT_MATCH_BPF) += xt_bpf.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CLUSTER) += xt_cluster.o
obj-$(CONFIG_NETFILTER_XT_MATCH_COMMENT) += xt_comment.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CONNBYTES) += xt_connbytes.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CONNLABEL) += xt_connlabel.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CONNLIMIT) += xt_connlimit.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CONNTRACK) += xt_conntrack.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CPU) += xt_cpu.o
obj-$(CONFIG_NETFILTER_XT_MATCH_DCCP) += xt_dccp.o
obj-$(CONFIG_NETFILTER_XT_MATCH_DEVGROUP) += xt_devgroup.o
obj-$(CONFIG_NETFILTER_XT_MATCH_DSCP) += xt_dscp.o
obj-$(CONFIG_NETFILTER_XT_MATCH_ECN) += xt_ecn.o
obj-$(CONFIG_NETFILTER_XT_MATCH_ESP) += xt_esp.o
obj-$(CONFIG_NETFILTER_XT_MATCH_HASHLIMIT) += xt_hashlimit.o
obj-$(CONFIG_NETFILTER_XT_MATCH_HELPER) += xt_helper.o
obj-$(CONFIG_NETFILTER_XT_MATCH_HL) += xt_hl.o
obj-$(CONFIG_NETFILTER_XT_MATCH_IPCOMP) += xt_ipcomp.o
obj-$(CONFIG_NETFILTER_XT_MATCH_IPRANGE) += xt_iprange.o
obj-$(CONFIG_NETFILTER_XT_MATCH_IPVS) += xt_ipvs.o
obj-$(CONFIG_NETFILTER_XT_MATCH_L2TP) += xt_l2tp.o
obj-$(CONFIG_NETFILTER_XT_MATCH_LENGTH) += xt_length.o
obj-$(CONFIG_NETFILTER_XT_MATCH_LIMIT) += xt_limit.o
obj-$(CONFIG_NETFILTER_XT_MATCH_MAC) += xt_mac.o
obj-$(CONFIG_NETFILTER_XT_MATCH_MULTIPORT) += xt_multiport.o
obj-$(CONFIG_NETFILTER_XT_MATCH_NFACCT) += xt_nfacct.o
obj-$(CONFIG_NETFILTER_XT_MATCH_OSF) += xt_osf.o
obj-$(CONFIG_NETFILTER_XT_MATCH_OWNER) += xt_owner.o
obj-$(CONFIG_NETFILTER_XT_MATCH_CGROUP) += xt_cgroup.o
obj-$(CONFIG_NETFILTER_XT_MATCH_PHYSDEV) += xt_physdev.o
obj-$(CONFIG_NETFILTER_XT_MATCH_PKTTYPE) += xt_pkttype.o
obj-$(CONFIG_NETFILTER_XT_MATCH_POLICY) += xt_policy.o
obj-$(CONFIG_NETFILTER_XT_MATCH_QUOTA) += xt_quota.o
obj-$(CONFIG_NETFILTER_XT_MATCH_RATEEST) += xt_rateest.o
obj-$(CONFIG_NETFILTER_XT_MATCH_REALM) += xt_realm.o
obj-$(CONFIG_NETFILTER_XT_MATCH_RECENT) += xt_recent.o
obj-$(CONFIG_NETFILTER_XT_MATCH_SCTP) += xt_sctp.o
obj-$(CONFIG_NETFILTER_XT_MATCH_SOCKET) += xt_socket.o
obj-$(CONFIG_NETFILTER_XT_MATCH_STATE) += xt_state.o
obj-$(CONFIG_NETFILTER_XT_MATCH_STATISTIC) += xt_statistic.o
obj-$(CONFIG_NETFILTER_XT_MATCH_STRING) += xt_string.o
obj-$(CONFIG_NETFILTER_XT_MATCH_TCPMSS) += xt_tcpmss.o
obj-$(CONFIG_NETFILTER_XT_MATCH_TIME) += xt_time.o
obj-$(CONFIG_NETFILTER_XT_MATCH_U32) += xt_u32.o

# ipset
obj-$(CONFIG_IP_SET) += ipset/

# IPVS
obj-$(CONFIG_IP_VS) += ipvs/

# lwtunnel
obj-$(CONFIG_LWTUNNEL) += nf_hooks_lwtunnel.o
