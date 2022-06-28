// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>

#if defined(CONFIG_NET)
struct io_async_msghdr {
	struct iovec			fast_iov[UIO_FASTIOV];
	/* points to an allocated iov, if NULL we use fast_iov instead */
	struct iovec			*free_iov;
	struct sockaddr __user		*uaddr;
	struct msghdr			msg;
	struct sockaddr_storage		addr;
};

struct io_async_connect {
	struct sockaddr_storage		address;
};

int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

int io_sendmsg_prep_async(struct io_kiocb *req);
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);
int io_send(struct io_kiocb *req, unsigned int issue_flags);

int io_recvmsg_prep_async(struct io_kiocb *req);
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);
int io_recv(struct io_kiocb *req, unsigned int issue_flags);

int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

int io_connect_prep_async(struct io_kiocb *req);
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_connect(struct io_kiocb *req, unsigned int issue_flags);
#endif
