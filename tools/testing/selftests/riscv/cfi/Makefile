CFLAGS += -I$(top_srcdir)/tools/include

CFLAGS += -march=rv64gc_zicfilp_zicfiss -fcf-protection=full

ifeq ($(shell $(CC) $(CFLAGS) -nostdlib -xc /dev/null -o /dev/null > /dev/null 2>&1; echo $$?),0)
TEST_GEN_PROGS := cfitests

include ../../lib.mk

$(OUTPUT)/cfitests: riscv_cfi_test.c shadowstack.c
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) $^
else
include ../../lib.mk

$(shell echo "Toolchain doesn't support CFI, skipping CFI kselftest." >&2)
endif
