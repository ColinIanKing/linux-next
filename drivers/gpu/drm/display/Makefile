# SPDX-License-Identifier: MIT

obj-$(CONFIG_DRM_DISPLAY_DP_AUX_BUS) += drm_dp_aux_bus.o

drm_display_helper-y := drm_display_helper_mod.o
drm_display_helper-$(CONFIG_DRM_BRIDGE_CONNECTOR) += \
	drm_bridge_connector.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_DP_HELPER) += \
	drm_dp_dual_mode_helper.o \
	drm_dp_helper.o \
	drm_dp_mst_topology.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_DP_TUNNEL) += \
	drm_dp_tunnel.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_DSC_HELPER) += \
	drm_dsc_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_HDCP_HELPER) += drm_hdcp_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_HDMI_AUDIO_HELPER) += \
	drm_hdmi_audio_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_HDMI_CEC_HELPER) += \
	drm_hdmi_cec_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_HDMI_CEC_NOTIFIER_HELPER) += \
	drm_hdmi_cec_notifier_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_HDMI_HELPER) += \
	drm_hdmi_helper.o \
	drm_scdc_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_HDMI_STATE_HELPER) += \
	drm_hdmi_state_helper.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_DP_AUX_CHARDEV) += drm_dp_aux_dev.o
drm_display_helper-$(CONFIG_DRM_DISPLAY_DP_AUX_CEC) += drm_dp_cec.o

obj-$(CONFIG_DRM_DISPLAY_HELPER) += drm_display_helper.o
