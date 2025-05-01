# SPDX-License-Identifier: GPL-2.0-only
#
# fixdep: used to generate dependency information during build process

hostprogs-always-y	+= fixdep

# randstruct: the seed is needed before building the gcc-plugin or
# before running a Clang kernel build.
gen-randstruct-seed	:= $(srctree)/scripts/gen-randstruct-seed.sh
quiet_cmd_create_randstruct_seed = GENSEED $@
      cmd_create_randstruct_seed = $(CONFIG_SHELL) $(gen-randstruct-seed) \
		$(obj)/randstruct.seed $(obj)/randstruct_hash.h

$(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
	$(call if_changed,create_randstruct_seed)

always-$(CONFIG_RANDSTRUCT) += randstruct.seed randstruct_hash.h

# integer-wrap: if the .scl file changes, we need to do a full rebuild.
quiet_cmd_integer_wrap_updated = UPDATE  $@
      cmd_integer_wrap_updated = echo '/* $^ */' > $(obj)/integer-wrap.h

$(obj)/integer-wrap.h: $(srctree)/scripts/integer-wrap-ignore.scl FORCE
	$(call if_changed,integer_wrap_updated)

always-$(CONFIG_UBSAN_INTEGER_WRAP) += integer-wrap.h
