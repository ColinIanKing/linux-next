# SPDX-License-Identifier: GPL-2.0
#
# Makefile for linux/drivers/platform/x86/lenovo
# Lenovo x86 Platform Specific Drivers
#
obj-$(CONFIG_IDEAPAD_LAPTOP)	+= ideapad-laptop.o
obj-$(CONFIG_THINKPAD_LMI)	+= think-lmi.o
obj-$(CONFIG_THINKPAD_ACPI)	+= thinkpad_acpi.o

lenovo-target-$(CONFIG_LENOVO_WMI_HOTKEY_UTILITIES)	+= wmi-hotkey-utilities.o
lenovo-target-$(CONFIG_LENOVO_YMC)	+= ymc.o
lenovo-target-$(CONFIG_YOGABOOK)	+= yogabook.o
lenovo-target-$(CONFIG_YT2_1380)	+= yoga-tab2-pro-1380-fastcharger.o
lenovo-target-$(CONFIG_LENOVO_WMI_CAMERA)	+= wmi-camera.o

# Add 'lenovo' prefix to each module listed in lenovo-target-*
define LENOVO_OBJ_TARGET
lenovo-$(1)-y := $(1).o
obj-$(2) += lenovo-$(1).o
endef

$(foreach target, $(basename $(lenovo-target-y)), $(eval $(call LENOVO_OBJ_TARGET,$(target),y)))
$(foreach target, $(basename $(lenovo-target-m)), $(eval $(call LENOVO_OBJ_TARGET,$(target),m)))
