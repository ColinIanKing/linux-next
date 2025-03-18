.. SPDX-License-Identifier: GPL-2.0

================
fwctl pds driver
================

:Author: Shannon Nelson

Overview
========

The PDS Core device makes an fwctl service available through an
auxiliary_device named pds_core.fwctl.N.  The pds_fwctl driver binds to
this device and registers itself with the fwctl subsystem.  The resulting
userspace interface is used by an application that is a part of the
AMD/Pensando software package for the Distributed Service Card (DSC).

The pds_fwctl driver has little knowledge of the firmware's internals,
only knows how to send commands through pds_core's message queue to the
firmware for fwctl requests.  The set of fwctl operations available
depends on the firmware in the DSC, and the userspace application
version must match the firmware so that they can talk to each other.

When a connection is created the pds_fwctl driver requests from the
firmware a list of firmware object endpoints, and for each endpoint the
driver requests a list of operations for the endpoint.  Each operation
description includes a minimum scope level that the pds_fwctl driver can
use for filtering privilege levels.

pds_fwctl User API
==================

.. kernel-doc:: include/uapi/fwctl/pds.h

Each RPC request includes the target endpoint and the operation id, and in
and out buffer lengths and pointers.  The driver verifies the existence
of the requested endpoint and operations, then checks the current scope
against the required scope of the operation.  The request is then put
together with the request data and sent through pds_core's message queue
to the firmware, and the results are returned to the caller.
