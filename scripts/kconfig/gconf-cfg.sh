#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

cflags=$1
libs=$2

PKG=gtk+-3.0

if [ -z "$(command -v ${HOSTPKG_CONFIG})" ]; then
	echo >&2 "*"
	echo >&2 "* 'make gconfig' requires '${HOSTPKG_CONFIG}'. Please install it."
	echo >&2 "*"
	exit 1
fi

if ! ${HOSTPKG_CONFIG} --exists $PKG; then
	echo >&2 "*"
	echo >&2 "* Unable to find the GTK+ installation. Please make sure that"
	echo >&2 "* the GTK 3 development package is correctly installed."
	echo >&2 "* You need $PKG"
	echo >&2 "*"
	exit 1
fi

${HOSTPKG_CONFIG} --cflags ${PKG} > ${cflags}
${HOSTPKG_CONFIG} --libs ${PKG} > ${libs}
