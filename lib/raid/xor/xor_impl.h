/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XOR_IMPL_H
#define _XOR_IMPL_H

#include <linux/init.h>
#include <linux/minmax.h>

struct xor_block_template {
	struct xor_block_template *next;
	const char *name;
	int speed;
	void (*xor_gen)(void *dest, void **srcs, unsigned int src_cnt,
			unsigned int bytes);
};

#define __DO_XOR_BLOCKS(_name, _handle1, _handle2, _handle3, _handle4)	\
void								\
xor_gen_##_name(void *dest, void **srcs, unsigned int src_cnt,		\
		unsigned int bytes)					\
{									\
	unsigned int src_off = 0;					\
									\
	while (src_cnt > 0) {						\
		unsigned int this_cnt = min(src_cnt, 4);		\
		unsigned long *p1 = (unsigned long *)srcs[src_off];	\
		unsigned long *p2 = (unsigned long *)srcs[src_off + 1];	\
		unsigned long *p3 = (unsigned long *)srcs[src_off + 2];	\
		unsigned long *p4 = (unsigned long *)srcs[src_off + 3];	\
									\
		if (this_cnt == 1)					\
			_handle1(bytes, dest, p1);			\
		else if (this_cnt == 2)					\
			_handle2(bytes, dest, p1, p2);			\
		else if (this_cnt == 3)					\
			_handle3(bytes, dest, p1, p2, p3);		\
		else							\
			_handle4(bytes, dest, p1, p2, p3, p4);		\
									\
		src_cnt -= this_cnt;					\
		src_off += this_cnt;					\
	}								\
}

#define DO_XOR_BLOCKS(_name, _handle1, _handle2, _handle3, _handle4)	\
	static __DO_XOR_BLOCKS(_name, _handle1, _handle2, _handle3, _handle4)

/* generic implementations */
extern struct xor_block_template xor_block_8regs;
extern struct xor_block_template xor_block_32regs;
extern struct xor_block_template xor_block_8regs_p;
extern struct xor_block_template xor_block_32regs_p;

void __init xor_register(struct xor_block_template *tmpl);
void __init xor_force(struct xor_block_template *tmpl);

#endif /* _XOR_IMPL_H */
