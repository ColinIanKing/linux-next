// SPDX-License-Identifier: GPL-2.0

/*
 * Kunit test for drm_hdmi_state_helper functions
 */

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_state_helper.h>
#include <drm/drm_atomic_uapi.h>
#include <drm/drm_drv.h>
#include <drm/drm_edid.h>
#include <drm/drm_connector.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_kunit_helpers.h>
#include <drm/drm_managed.h>
#include <drm/drm_modeset_helper_vtables.h>
#include <drm/drm_print.h>
#include <drm/drm_probe_helper.h>

#include <drm/display/drm_hdmi_helper.h>
#include <drm/display/drm_hdmi_state_helper.h>

#include "../drm_crtc_internal.h"

#include <kunit/test.h>

#include "drm_kunit_edid.h"

struct drm_atomic_helper_connector_hdmi_priv {
	struct drm_device drm;
	struct drm_plane *plane;
	struct drm_crtc *crtc;
	struct drm_encoder encoder;
	struct drm_connector connector;

	const void *current_edid;
	size_t current_edid_len;
};

#define connector_to_priv(c) \
	container_of_const(c, struct drm_atomic_helper_connector_hdmi_priv, connector)

static struct drm_display_mode *find_preferred_mode(struct drm_connector *connector)
{
	struct drm_device *drm = connector->dev;
	struct drm_display_mode *mode, *preferred;

	mutex_lock(&drm->mode_config.mutex);
	preferred = list_first_entry_or_null(&connector->modes, struct drm_display_mode, head);
	list_for_each_entry(mode, &connector->modes, head)
		if (mode->type & DRM_MODE_TYPE_PREFERRED)
			preferred = mode;
	mutex_unlock(&drm->mode_config.mutex);

	return preferred;
}

static int set_connector_edid(struct kunit *test, struct drm_connector *connector,
			      const void *edid, size_t edid_len)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv =
		connector_to_priv(connector);
	struct drm_device *drm = connector->dev;
	int ret;

	priv->current_edid = edid;
	priv->current_edid_len = edid_len;

	mutex_lock(&drm->mode_config.mutex);
	ret = connector->funcs->fill_modes(connector, 4096, 4096);
	mutex_unlock(&drm->mode_config.mutex);

	return ret;
}

static const struct drm_connector_hdmi_funcs dummy_connector_hdmi_funcs = {
};

static enum drm_mode_status
reject_connector_tmds_char_rate_valid(const struct drm_connector *connector,
				      const struct drm_display_mode *mode,
				      unsigned long long tmds_rate)
{
	return MODE_BAD;
}

static const struct drm_connector_hdmi_funcs reject_connector_hdmi_funcs = {
	.tmds_char_rate_valid	= reject_connector_tmds_char_rate_valid,
};

static enum drm_mode_status
reject_100mhz_connector_tmds_char_rate_valid(const struct drm_connector *connector,
					     const struct drm_display_mode *mode,
					     unsigned long long tmds_rate)
{
	return (tmds_rate > 100ULL * 1000 * 1000) ? MODE_BAD : MODE_OK;
}

static const struct drm_connector_hdmi_funcs reject_100mhz_connector_hdmi_funcs = {
	.tmds_char_rate_valid	= reject_100mhz_connector_tmds_char_rate_valid,
};

static int dummy_connector_get_modes(struct drm_connector *connector)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv =
		connector_to_priv(connector);
	const struct drm_edid *edid;
	unsigned int num_modes;

	edid = drm_edid_alloc(priv->current_edid, priv->current_edid_len);
	if (!edid)
		return -EINVAL;

	drm_edid_connector_update(connector, edid);
	num_modes = drm_edid_connector_add_modes(connector);

	drm_edid_free(edid);

	return num_modes;
}

static const struct drm_connector_helper_funcs dummy_connector_helper_funcs = {
	.atomic_check	= drm_atomic_helper_connector_hdmi_check,
	.get_modes	= dummy_connector_get_modes,
	.mode_valid	= drm_hdmi_connector_mode_valid,
};

static void dummy_hdmi_connector_reset(struct drm_connector *connector)
{
	drm_atomic_helper_connector_reset(connector);
	__drm_atomic_helper_connector_hdmi_reset(connector, connector->state);
}

static const struct drm_connector_funcs dummy_connector_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.fill_modes		= drm_helper_probe_single_connector_modes,
	.reset			= dummy_hdmi_connector_reset,
};

static
struct drm_atomic_helper_connector_hdmi_priv *
__connector_hdmi_init(struct kunit *test,
		      unsigned int formats,
		      unsigned int max_bpc,
		      const struct drm_connector_hdmi_funcs *hdmi_funcs,
		      const void *edid_data, size_t edid_len)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector *conn;
	struct drm_encoder *enc;
	struct drm_device *drm;
	struct device *dev;
	int ret;

	dev = drm_kunit_helper_alloc_device(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dev);

	priv = drm_kunit_helper_alloc_drm_device(test, dev,
						 struct drm_atomic_helper_connector_hdmi_priv, drm,
						 DRIVER_MODESET | DRIVER_ATOMIC);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv);
	test->priv = priv;

	drm = &priv->drm;
	priv->plane = drm_kunit_helper_create_primary_plane(test, drm,
							    NULL,
							    NULL,
							    NULL, 0,
							    NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv->plane);

	priv->crtc = drm_kunit_helper_create_crtc(test, drm,
						  priv->plane, NULL,
						  NULL,
						  NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv->crtc);

	enc = &priv->encoder;
	ret = drmm_encoder_init(drm, enc, NULL, DRM_MODE_ENCODER_TMDS, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);

	enc->possible_crtcs = drm_crtc_mask(priv->crtc);

	conn = &priv->connector;
	conn->ycbcr_420_allowed = !!(formats & BIT(HDMI_COLORSPACE_YUV420));

	ret = drmm_connector_hdmi_init(drm, conn,
				       "Vendor", "Product",
				       &dummy_connector_funcs,
				       hdmi_funcs,
				       DRM_MODE_CONNECTOR_HDMIA,
				       NULL,
				       formats,
				       max_bpc);
	KUNIT_ASSERT_EQ(test, ret, 0);

	drm_connector_helper_add(conn, &dummy_connector_helper_funcs);
	drm_connector_attach_encoder(conn, enc);

	drm_mode_config_reset(drm);

	if (edid_data && edid_len) {
		ret = set_connector_edid(test, &priv->connector, edid_data, edid_len);
		KUNIT_ASSERT_GT(test, ret, 0);
	}

	return priv;
}

#define drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test, formats, max_bpc, funcs, edid) \
	__connector_hdmi_init(test, formats, max_bpc, funcs, edid, ARRAY_SIZE(edid))

static
struct drm_atomic_helper_connector_hdmi_priv *
drm_kunit_helper_connector_hdmi_init(struct kunit *test,
				     unsigned int formats,
				     unsigned int max_bpc)
{
	return drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				formats,
				max_bpc,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_max_200mhz);
}

/*
 * Test that if we change the RGB quantization property to a different
 * value, we trigger a mode change on the connector's CRTC, which will
 * in turn disable/enable the connector.
 */
static void drm_test_check_broadcast_rgb_crtc_mode_changed(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *old_conn_state;
	struct drm_connector_state *new_conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	new_conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	new_conn_state->hdmi.broadcast_rgb = DRM_HDMI_BROADCAST_RGB_FULL;

	KUNIT_ASSERT_NE(test,
			old_conn_state->hdmi.broadcast_rgb,
			new_conn_state->hdmi.broadcast_rgb);

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	new_conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);
	KUNIT_EXPECT_EQ(test, new_conn_state->hdmi.broadcast_rgb, DRM_HDMI_BROADCAST_RGB_FULL);

	crtc_state = drm_atomic_get_new_crtc_state(state, crtc);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);
	KUNIT_EXPECT_TRUE(test, crtc_state->mode_changed);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if we set the RGB quantization property to the same value,
 * we don't trigger a mode change on the connector's CRTC and leave the
 * connector unaffected.
 */
static void drm_test_check_broadcast_rgb_crtc_mode_not_changed(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *old_conn_state;
	struct drm_connector_state *new_conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	new_conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	new_conn_state->hdmi.broadcast_rgb = old_conn_state->hdmi.broadcast_rgb;

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	new_conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	KUNIT_EXPECT_EQ(test,
			old_conn_state->hdmi.broadcast_rgb,
			new_conn_state->hdmi.broadcast_rgb);

	crtc_state = drm_atomic_get_new_crtc_state(state, crtc);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);
	KUNIT_EXPECT_FALSE(test, crtc_state->mode_changed);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, if the
 * Broadcast RGB property is set to auto with a mode that isn't the
 * VIC-1 mode, we will get a limited RGB Quantization Range.
 */
static void drm_test_check_broadcast_rgb_auto_cea_mode(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_NE(test, drm_match_cea_mode(preferred), 1);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test,
			conn_state->hdmi.broadcast_rgb,
			DRM_HDMI_BROADCAST_RGB_AUTO);

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_EXPECT_TRUE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, if the
 * Broadcast RGB property is set to auto with a VIC-1 mode, we will get
 * a full RGB Quantization Range.
 */
static void drm_test_check_broadcast_rgb_auto_cea_mode_vic_1(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *mode;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	drm_modeset_acquire_init(&ctx, 0);

	mode = drm_kunit_display_mode_from_cea_vic(test, drm, 1);
	KUNIT_ASSERT_NOT_NULL(test, mode);

	crtc = priv->crtc;
	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     mode,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test,
			conn_state->hdmi.broadcast_rgb,
			DRM_HDMI_BROADCAST_RGB_AUTO);

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_EXPECT_FALSE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, if the
 * Broadcast RGB property is set to full with a mode that isn't the
 * VIC-1 mode, we will get a full RGB Quantization Range.
 */
static void drm_test_check_broadcast_rgb_full_cea_mode(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_NE(test, drm_match_cea_mode(preferred), 1);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	conn_state->hdmi.broadcast_rgb = DRM_HDMI_BROADCAST_RGB_FULL;

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test,
			conn_state->hdmi.broadcast_rgb,
			DRM_HDMI_BROADCAST_RGB_FULL);

	KUNIT_EXPECT_FALSE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, if the
 * Broadcast RGB property is set to full with a VIC-1 mode, we will get
 * a full RGB Quantization Range.
 */
static void drm_test_check_broadcast_rgb_full_cea_mode_vic_1(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *mode;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	drm_modeset_acquire_init(&ctx, 0);

	mode = drm_kunit_display_mode_from_cea_vic(test, drm, 1);
	KUNIT_ASSERT_NOT_NULL(test, mode);

	crtc = priv->crtc;
	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     mode,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	conn_state->hdmi.broadcast_rgb = DRM_HDMI_BROADCAST_RGB_FULL;

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test,
			conn_state->hdmi.broadcast_rgb,
			DRM_HDMI_BROADCAST_RGB_FULL);

	KUNIT_EXPECT_FALSE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, if the
 * Broadcast RGB property is set to limited with a mode that isn't the
 * VIC-1 mode, we will get a limited RGB Quantization Range.
 */
static void drm_test_check_broadcast_rgb_limited_cea_mode(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_NE(test, drm_match_cea_mode(preferred), 1);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	conn_state->hdmi.broadcast_rgb = DRM_HDMI_BROADCAST_RGB_LIMITED;

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test,
			conn_state->hdmi.broadcast_rgb,
			DRM_HDMI_BROADCAST_RGB_LIMITED);

	KUNIT_EXPECT_TRUE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, if the
 * Broadcast RGB property is set to limited with a VIC-1 mode, we will
 * get a limited RGB Quantization Range.
 */
static void drm_test_check_broadcast_rgb_limited_cea_mode_vic_1(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *mode;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	drm_modeset_acquire_init(&ctx, 0);

	mode = drm_kunit_display_mode_from_cea_vic(test, drm, 1);
	KUNIT_ASSERT_NOT_NULL(test, mode);

	crtc = priv->crtc;
	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     mode,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	conn_state->hdmi.broadcast_rgb = DRM_HDMI_BROADCAST_RGB_LIMITED;

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test,
			conn_state->hdmi.broadcast_rgb,
			DRM_HDMI_BROADCAST_RGB_LIMITED);

	KUNIT_EXPECT_TRUE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that for an HDMI connector, with an HDMI monitor, we will
 * get a limited RGB Quantization Range with a YUV420 mode, no
 * matter what the value of the Broadcast RGB property is set to.
 */
static void drm_test_check_broadcast_rgb_cea_mode_yuv420(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	enum drm_hdmi_broadcast_rgb broadcast_rgb;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *mode;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	broadcast_rgb = *(enum drm_hdmi_broadcast_rgb *)test->param_value;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV420),
				8,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_4k_yuv420_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	KUNIT_ASSERT_TRUE(test, conn->display_info.is_hdmi);

	mode = drm_kunit_display_mode_from_cea_vic(test, drm, 95);
	KUNIT_ASSERT_NOT_NULL(test, mode);

	drm_modeset_acquire_init(&ctx, 0);

retry_conn_enable:
	ret = drm_kunit_helper_enable_crtc_connector(test, drm, crtc, conn,
						     mode, &ctx);
	if (ret == -EDEADLK) {
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_conn_enable;
	}
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

retry_conn_state:
	conn_state = drm_atomic_get_connector_state(state, conn);
	if (PTR_ERR(conn_state) == -EDEADLK) {
		drm_atomic_state_clear(state);
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_conn_state;
	}
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	conn_state->hdmi.broadcast_rgb = broadcast_rgb;

	ret = drm_atomic_check_only(state);
	if (ret == -EDEADLK) {
		drm_atomic_state_clear(state);
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_conn_state;
	}
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test, conn_state->hdmi.broadcast_rgb, broadcast_rgb);
	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_YUV420);

	KUNIT_EXPECT_TRUE(test, conn_state->hdmi.is_limited_range);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

static const enum drm_hdmi_broadcast_rgb check_broadcast_rgb_cea_mode_yuv420_tests[] = {
	DRM_HDMI_BROADCAST_RGB_AUTO,
	DRM_HDMI_BROADCAST_RGB_FULL,
	DRM_HDMI_BROADCAST_RGB_LIMITED,
};

static void
check_broadcast_rgb_cea_mode_yuv420_desc(const enum drm_hdmi_broadcast_rgb *broadcast_rgb,
					 char *desc)
{
	sprintf(desc, "%s", drm_hdmi_connector_get_broadcast_rgb_name(*broadcast_rgb));
}

KUNIT_ARRAY_PARAM(check_broadcast_rgb_cea_mode_yuv420,
		  check_broadcast_rgb_cea_mode_yuv420_tests,
		  check_broadcast_rgb_cea_mode_yuv420_desc);

/*
 * Test that if we change the maximum bpc property to a different value,
 * we trigger a mode change on the connector's CRTC, which will in turn
 * disable/enable the connector.
 */
static void drm_test_check_output_bpc_crtc_mode_changed(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *old_conn_state;
	struct drm_connector_state *new_conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				10,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	new_conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	new_conn_state->max_requested_bpc = 8;

	KUNIT_ASSERT_NE(test,
			old_conn_state->max_requested_bpc,
			new_conn_state->max_requested_bpc);

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	new_conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	KUNIT_ASSERT_NE(test,
			old_conn_state->hdmi.output_bpc,
			new_conn_state->hdmi.output_bpc);

	crtc_state = drm_atomic_get_new_crtc_state(state, crtc);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);
	KUNIT_EXPECT_TRUE(test, crtc_state->mode_changed);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if we set the output bpc property to the same value, we
 * don't trigger a mode change on the connector's CRTC and leave the
 * connector unaffected.
 */
static void drm_test_check_output_bpc_crtc_mode_not_changed(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *old_conn_state;
	struct drm_connector_state *new_conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				10,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	new_conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	KUNIT_ASSERT_EQ(test,
			new_conn_state->hdmi.output_bpc,
			old_conn_state->hdmi.output_bpc);

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	old_conn_state = drm_atomic_get_old_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, old_conn_state);

	new_conn_state = drm_atomic_get_new_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, new_conn_state);

	KUNIT_EXPECT_EQ(test,
			old_conn_state->hdmi.output_bpc,
			new_conn_state->hdmi.output_bpc);

	crtc_state = drm_atomic_get_new_crtc_state(state, crtc);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);
	KUNIT_EXPECT_FALSE(test, crtc_state->mode_changed);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if we have an HDMI connector but a !HDMI display, we always
 * output RGB with 8 bpc.
 */
static void drm_test_check_output_bpc_dvi(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV422) |
				BIT(HDMI_COLORSPACE_YUV444),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_dvi_1080p);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_FALSE(test, info->is_hdmi);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that when doing a commit which would use RGB 8bpc, the TMDS
 * clock rate stored in the connector state is equal to the mode clock
 */
static void drm_test_check_tmds_char_rate_rgb_8bpc(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				8,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, preferred->flags & DRM_MODE_FLAG_DBLCLK);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_bpc, 8);
	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.tmds_char_rate, preferred->clock * 1000);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that when doing a commit which would use RGB 10bpc, the TMDS
 * clock rate stored in the connector state is equal to 1.25 times the
 * mode pixel clock
 */
static void drm_test_check_tmds_char_rate_rgb_10bpc(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				10,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_340mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, preferred->flags & DRM_MODE_FLAG_DBLCLK);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_bpc, 10);
	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.tmds_char_rate, preferred->clock * 1250);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that when doing a commit which would use RGB 12bpc, the TMDS
 * clock rate stored in the connector state is equal to 1.5 times the
 * mode pixel clock
 */
static void drm_test_check_tmds_char_rate_rgb_12bpc(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_340mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, preferred->flags & DRM_MODE_FLAG_DBLCLK);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_bpc, 12);
	KUNIT_ASSERT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.tmds_char_rate, preferred->clock * 1500);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if we filter a rate through our hook, it's indeed rejected
 * by the whole atomic_check logic.
 *
 * We do so by first doing a commit on the pipeline to make sure that it
 * works, change the HDMI helpers pointer, and then try the same commit
 * again to see if it fails as it should.
 */
static void drm_test_check_hdmi_funcs_reject_rate(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_crtc_state *crtc_state;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* You shouldn't be doing that at home. */
	conn->hdmi.funcs = &reject_connector_hdmi_funcs;

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	crtc_state = drm_atomic_get_crtc_state(state, crtc);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);

	crtc_state->connectors_changed = true;

	ret = drm_atomic_check_only(state);
	KUNIT_EXPECT_LT(test, ret, 0);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if:
 * - We have an HDMI connector supporting RGB only
 * - The chosen mode has a TMDS character rate higher than the display
 *   supports in RGB/12bpc
 * - The chosen mode has a TMDS character rate lower than the display
 *   supports in RGB/10bpc.
 *
 * Then we will pick the latter, and the computed TMDS character rate
 * will be equal to 1.25 times the mode pixel clock.
 */
static void drm_test_check_max_tmds_rate_bpc_fallback_rgb(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, preferred->flags & DRM_MODE_FLAG_DBLCLK);

	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_GT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 10, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 10);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.tmds_char_rate, preferred->clock * 1250);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if:
 * - We have an HDMI connector and a display supporting both RGB and YUV420
 * - The chosen mode can be supported in YUV420 output format only
 * - The chosen mode has a TMDS character rate higher than the display
 *   supports in YUV420/12bpc
 * - The chosen mode has a TMDS character rate lower than the display
 *   supports in YUV420/10bpc.
 *
 * Then we will pick the latter, and the computed TMDS character rate
 * will be equal to 1.25 * 0.5 times the mode pixel clock.
 */
static void drm_test_check_max_tmds_rate_bpc_fallback_yuv420(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *yuv420_only_mode;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV420),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_4k_yuv420_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);
	KUNIT_ASSERT_TRUE(test, conn->ycbcr_420_allowed);

	yuv420_only_mode = drm_kunit_display_mode_from_cea_vic(test, drm, 95);
	KUNIT_ASSERT_NOT_NULL(test, yuv420_only_mode);
	KUNIT_ASSERT_TRUE(test, drm_mode_is_420_only(info, yuv420_only_mode));

	rate = drm_hdmi_compute_mode_clock(yuv420_only_mode, 12, HDMI_COLORSPACE_YUV420);
	KUNIT_ASSERT_GT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(yuv420_only_mode, 10, HDMI_COLORSPACE_YUV420);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

retry_conn_enable:
	ret = drm_kunit_helper_enable_crtc_connector(test, drm, crtc, conn,
						     yuv420_only_mode, &ctx);
	if (ret == -EDEADLK) {
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_conn_enable;
	}
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 10);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_YUV420);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.tmds_char_rate, yuv420_only_mode->clock * 625);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if:
 * - We have an HDMI connector supporting both RGB and YUV422 and up to
 *   12 bpc
 * - The chosen mode has a TMDS character rate higher than the display
 *   supports in RGB/12bpc but lower than the display supports in
 *   RGB/10bpc
 * - The chosen mode has a TMDS character rate lower than the display
 *   supports in YUV422/12bpc.
 *
 * Then we will prefer to keep the RGB format with a lower bpc over
 * picking YUV422.
 */
static void drm_test_check_max_tmds_rate_bpc_fallback_ignore_yuv422(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV422) |
				BIT(HDMI_COLORSPACE_YUV444),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, preferred->flags & DRM_MODE_FLAG_DBLCLK);

	rate = drm_hdmi_compute_mode_clock(preferred, 10, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_GT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_YUV422);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 10);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if:
 * - We have an HDMI connector supporting both RGB and YUV420 and up to
 *   12 bpc
 * - The chosen mode has a TMDS character rate higher than the display
 *   supports in RGB/10bpc but lower than the display supports in
 *   RGB/8bpc
 * - The chosen mode has a TMDS character rate lower than the display
 *   supports in YUV420/12bpc.
 *
 * Then we will prefer to keep the RGB format with a lower bpc over
 * picking YUV420.
 */
static void drm_test_check_max_tmds_rate_bpc_fallback_ignore_yuv420(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV420),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_4k_rgb_yuv420_dc_max_340mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);
	KUNIT_ASSERT_TRUE(test, conn->ycbcr_420_allowed);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, preferred->flags & DRM_MODE_FLAG_DBLCLK);
	KUNIT_ASSERT_TRUE(test, drm_mode_is_420_also(info, preferred));

	rate = drm_hdmi_compute_mode_clock(preferred, 8, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 10, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_GT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_YUV420);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

retry_conn_enable:
	ret = drm_kunit_helper_enable_crtc_connector(test, drm, crtc, conn,
						     preferred, &ctx);
	if (ret == -EDEADLK) {
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_conn_enable;
	}
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if a driver supports only RGB, but the chosen mode can be
 * supported by the screen only in YUV420 output format, we end up with
 * unsuccessful fallback attempts.
 */
static void drm_test_check_driver_unsupported_fallback_yuv420(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_atomic_state *state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred, *yuv420_only_mode;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_4k_yuv420_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_FALSE(test, conn->ycbcr_420_allowed);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_ASSERT_FALSE(test, drm_mode_is_420_also(info, preferred));

	yuv420_only_mode = drm_kunit_display_mode_from_cea_vic(test, drm, 95);
	KUNIT_ASSERT_NOT_NULL(test, yuv420_only_mode);
	KUNIT_ASSERT_TRUE(test, drm_mode_is_420_only(info, yuv420_only_mode));

	drm_modeset_acquire_init(&ctx, 0);

retry_conn_enable:
	ret = drm_kunit_helper_enable_crtc_connector(test, drm, crtc, conn,
						     preferred, &ctx);
	if (ret == -EDEADLK) {
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_conn_enable;
	}
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

retry_crtc_state:
	crtc_state = drm_atomic_get_crtc_state(state, crtc);
	if (PTR_ERR(crtc_state) == -EDEADLK) {
		drm_atomic_state_clear(state);
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_crtc_state;
	}
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);

	ret = drm_atomic_set_mode_for_crtc(crtc_state, yuv420_only_mode);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = drm_atomic_check_only(state);
	if (ret == -EDEADLK) {
		drm_atomic_state_clear(state);
		ret = drm_modeset_backoff(&ctx);
		if (!ret)
			goto retry_crtc_state;
	}
	KUNIT_ASSERT_LT(test, ret, 0);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if a driver and screen supports RGB and YUV formats, and we
 * try to set the VIC 1 mode, we end up with 8bpc RGB even if we could
 * have had a higher bpc.
 */
static void drm_test_check_output_bpc_format_vic_1(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *mode;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV422) |
				BIT(HDMI_COLORSPACE_YUV444),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	mode = drm_kunit_display_mode_from_cea_vic(test, drm, 1);
	KUNIT_ASSERT_NOT_NULL(test, mode);

	/*
	 * NOTE: We can't use drm_hdmi_compute_mode_clock()
	 * here because we're trying to get the rate of an invalid
	 * configuration.
	 *
	 * Thus, we have to calculate the rate by hand.
	 */
	rate = mode->clock * 1500;
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	crtc = priv->crtc;
	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     mode,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if a driver supports only RGB but the screen also supports
 * YUV formats, we only end up with an RGB format.
 */
static void drm_test_check_output_bpc_format_driver_rgb_only(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	/*
	 * We're making sure that YUV422 would be the preferred option
	 * here: we're always favouring higher bpc, we can't have RGB
	 * because the TMDS character rate exceeds the maximum supported
	 * by the display, and YUV422 works for that display.
	 *
	 * But since the driver only supports RGB, we should fallback to
	 * a lower bpc with RGB.
	 */
	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_GT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_YUV422);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_LT(test, conn_state->hdmi.output_bpc, 12);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if a screen supports only RGB but the driver also supports
 * YUV formats, we only end up with an RGB format.
 */
static void drm_test_check_output_bpc_format_display_rgb_only(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV422) |
				BIT(HDMI_COLORSPACE_YUV444),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	/*
	 * We're making sure that YUV422 would be the preferred option
	 * here: we're always favouring higher bpc, we can't have RGB
	 * because the TMDS character rate exceeds the maximum supported
	 * by the display, and YUV422 works for that display.
	 *
	 * But since the display only supports RGB, we should fallback to
	 * a lower bpc with RGB.
	 */
	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_GT(test, rate, info->max_tmds_clock * 1000);

	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_YUV422);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_LT(test, conn_state->hdmi.output_bpc, 12);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if a display supports higher bpc but the driver only
 * supports 8 bpc, we only end up with 8 bpc even if we could have had a
 * higher bpc.
 */
static void drm_test_check_output_bpc_format_driver_8bpc_only(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				8,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_yuv_dc_max_340mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	/*
	 * We're making sure that we have headroom on the TMDS character
	 * clock to actually use 12bpc.
	 */
	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/*
 * Test that if a driver supports higher bpc but the display only
 * supports 8 bpc, we only end up with 8 bpc even if we could have had a
 * higher bpc.
 */
static void drm_test_check_output_bpc_format_display_8bpc_only(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_display_info *info;
	struct drm_display_mode *preferred;
	unsigned long long rate;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB) |
				BIT(HDMI_COLORSPACE_YUV422) |
				BIT(HDMI_COLORSPACE_YUV444),
				12,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_max_340mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm = &priv->drm;
	crtc = priv->crtc;
	conn = &priv->connector;
	info = &conn->display_info;
	KUNIT_ASSERT_TRUE(test, info->is_hdmi);
	KUNIT_ASSERT_GT(test, info->max_tmds_clock, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	/*
	 * We're making sure that we have headroom on the TMDS character
	 * clock to actually use 12bpc.
	 */
	rate = drm_hdmi_compute_mode_clock(preferred, 12, HDMI_COLORSPACE_RGB);
	KUNIT_ASSERT_LT(test, rate, info->max_tmds_clock * 1000);

	drm_modeset_acquire_init(&ctx, 0);

	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = conn->state;
	KUNIT_ASSERT_NOT_NULL(test, conn_state);

	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, HDMI_COLORSPACE_RGB);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

/* Test that atomic check succeeds when disabling a connector. */
static void drm_test_check_disable_connector(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_connector_state *conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_atomic_state *state;
	struct drm_display_mode *preferred;
	struct drm_connector *conn;
	struct drm_device *drm;
	struct drm_crtc *crtc;
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	drm_modeset_acquire_init(&ctx, 0);

	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	drm = &priv->drm;
	crtc = priv->crtc;
	ret = drm_kunit_helper_enable_crtc_connector(test, drm,
						     crtc, conn,
						     preferred,
						     &ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	state = drm_kunit_helper_atomic_state_alloc(test, drm, &ctx);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, state);

	crtc_state = drm_atomic_get_crtc_state(state, crtc);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, crtc_state);

	crtc_state->active = false;
	ret = drm_atomic_set_mode_for_crtc(crtc_state, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	conn_state = drm_atomic_get_connector_state(state, conn);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn_state);

	ret = drm_atomic_set_crtc_for_connector(conn_state, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = drm_atomic_check_only(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);
}

static struct kunit_case drm_atomic_helper_connector_hdmi_check_tests[] = {
	KUNIT_CASE(drm_test_check_broadcast_rgb_auto_cea_mode),
	KUNIT_CASE(drm_test_check_broadcast_rgb_auto_cea_mode_vic_1),
	KUNIT_CASE(drm_test_check_broadcast_rgb_full_cea_mode),
	KUNIT_CASE(drm_test_check_broadcast_rgb_full_cea_mode_vic_1),
	KUNIT_CASE(drm_test_check_broadcast_rgb_limited_cea_mode),
	KUNIT_CASE(drm_test_check_broadcast_rgb_limited_cea_mode_vic_1),
	KUNIT_CASE_PARAM(drm_test_check_broadcast_rgb_cea_mode_yuv420,
			 check_broadcast_rgb_cea_mode_yuv420_gen_params),
	KUNIT_CASE(drm_test_check_broadcast_rgb_crtc_mode_changed),
	KUNIT_CASE(drm_test_check_broadcast_rgb_crtc_mode_not_changed),
	KUNIT_CASE(drm_test_check_disable_connector),
	KUNIT_CASE(drm_test_check_hdmi_funcs_reject_rate),
	KUNIT_CASE(drm_test_check_max_tmds_rate_bpc_fallback_rgb),
	KUNIT_CASE(drm_test_check_max_tmds_rate_bpc_fallback_yuv420),
	KUNIT_CASE(drm_test_check_max_tmds_rate_bpc_fallback_ignore_yuv422),
	KUNIT_CASE(drm_test_check_max_tmds_rate_bpc_fallback_ignore_yuv420),
	KUNIT_CASE(drm_test_check_driver_unsupported_fallback_yuv420),
	KUNIT_CASE(drm_test_check_output_bpc_crtc_mode_changed),
	KUNIT_CASE(drm_test_check_output_bpc_crtc_mode_not_changed),
	KUNIT_CASE(drm_test_check_output_bpc_dvi),
	KUNIT_CASE(drm_test_check_output_bpc_format_vic_1),
	KUNIT_CASE(drm_test_check_output_bpc_format_display_8bpc_only),
	KUNIT_CASE(drm_test_check_output_bpc_format_display_rgb_only),
	KUNIT_CASE(drm_test_check_output_bpc_format_driver_8bpc_only),
	KUNIT_CASE(drm_test_check_output_bpc_format_driver_rgb_only),
	KUNIT_CASE(drm_test_check_tmds_char_rate_rgb_8bpc),
	KUNIT_CASE(drm_test_check_tmds_char_rate_rgb_10bpc),
	KUNIT_CASE(drm_test_check_tmds_char_rate_rgb_12bpc),
	/*
	 * TODO: We should have tests to check that a change in the
	 * format triggers a CRTC mode change just like we do for the
	 * RGB Quantization and BPC.
	 *
	 * However, we don't have any way to control which format gets
	 * picked up aside from changing the BPC or mode which would
	 * already trigger a mode change.
	 */
	{ }
};

static struct kunit_suite drm_atomic_helper_connector_hdmi_check_test_suite = {
	.name		= "drm_atomic_helper_connector_hdmi_check",
	.test_cases	= drm_atomic_helper_connector_hdmi_check_tests,
};

/*
 * Test that the value of the Broadcast RGB property out of reset is set
 * to auto.
 */
static void drm_test_check_broadcast_rgb_value(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	conn_state = conn->state;
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.broadcast_rgb, DRM_HDMI_BROADCAST_RGB_AUTO);
}

/*
 * Test that if the connector was initialised with a maximum bpc of 8,
 * the value of the max_bpc and max_requested_bpc properties out of
 * reset are also set to 8, and output_bpc is set to 0 and will be
 * filled at atomic_check time.
 */
static void drm_test_check_bpc_8_value(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	conn_state = conn->state;
	KUNIT_EXPECT_EQ(test, conn_state->max_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->max_requested_bpc, 8);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 0);
}

/*
 * Test that if the connector was initialised with a maximum bpc of 10,
 * the value of the max_bpc and max_requested_bpc properties out of
 * reset are also set to 10, and output_bpc is set to 0 and will be
 * filled at atomic_check time.
 */
static void drm_test_check_bpc_10_value(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    10);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	conn_state = conn->state;
	KUNIT_EXPECT_EQ(test, conn_state->max_bpc, 10);
	KUNIT_EXPECT_EQ(test, conn_state->max_requested_bpc, 10);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 0);
}

/*
 * Test that if the connector was initialised with a maximum bpc of 12,
 * the value of the max_bpc and max_requested_bpc properties out of
 * reset are also set to 12, and output_bpc is set to 0 and will be
 * filled at atomic_check time.
 */
static void drm_test_check_bpc_12_value(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    12);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	conn_state = conn->state;
	KUNIT_EXPECT_EQ(test, conn_state->max_bpc, 12);
	KUNIT_EXPECT_EQ(test, conn_state->max_requested_bpc, 12);
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_bpc, 0);
}

/*
 * Test that the value of the output format property out of reset is set
 * to RGB, even if the driver supports more than that.
 */
static void drm_test_check_format_value(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB) |
						    BIT(HDMI_COLORSPACE_YUV422) |
						    BIT(HDMI_COLORSPACE_YUV444),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	conn_state = conn->state;
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.output_format, 0);
}

/*
 * Test that the value of the output format property out of reset is set
 * to 0, and will be computed at atomic_check time.
 */
static void drm_test_check_tmds_char_value(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB) |
						    BIT(HDMI_COLORSPACE_YUV422) |
						    BIT(HDMI_COLORSPACE_YUV444),
						    12);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	conn_state = conn->state;
	KUNIT_EXPECT_EQ(test, conn_state->hdmi.tmds_char_rate, 0);
}

static struct kunit_case drm_atomic_helper_connector_hdmi_reset_tests[] = {
	KUNIT_CASE(drm_test_check_broadcast_rgb_value),
	KUNIT_CASE(drm_test_check_bpc_8_value),
	KUNIT_CASE(drm_test_check_bpc_10_value),
	KUNIT_CASE(drm_test_check_bpc_12_value),
	KUNIT_CASE(drm_test_check_format_value),
	KUNIT_CASE(drm_test_check_tmds_char_value),
	{ }
};

static struct kunit_suite drm_atomic_helper_connector_hdmi_reset_test_suite = {
	.name		= "drm_atomic_helper_connector_hdmi_reset",
	.test_cases	= drm_atomic_helper_connector_hdmi_reset_tests,
};

/*
 * Test that the default behaviour for drm_hdmi_connector_mode_valid() is not
 * to reject any modes. Pass a correct EDID and verify that preferred mode
 * matches the expectations (1080p).
 */
static void drm_test_check_mode_valid(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector *conn;
	struct drm_display_mode *preferred;

	priv = drm_kunit_helper_connector_hdmi_init(test,
						    BIT(HDMI_COLORSPACE_RGB),
						    8);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);

	KUNIT_EXPECT_EQ(test, preferred->hdisplay, 1920);
	KUNIT_EXPECT_EQ(test, preferred->vdisplay, 1080);
	KUNIT_EXPECT_EQ(test, preferred->clock, 148500);
}

/*
 * Test that the drm_hdmi_connector_mode_valid() will reject modes depending on
 * the .tmds_char_rate_valid() behaviour.
 * Pass a correct EDID and verify that high-rate modes are filtered.
 */
static void drm_test_check_mode_valid_reject_rate(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_display_mode *preferred;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
					BIT(HDMI_COLORSPACE_RGB),
					8,
					&reject_100mhz_connector_hdmi_funcs,
					test_edid_hdmi_1080p_rgb_max_200mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	/*
	 * Unlike the drm_test_check_mode_valid() here 1080p is rejected, but
	 * 480p is allowed.
	 */
	preferred = find_preferred_mode(&priv->connector);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_EXPECT_EQ(test, preferred->hdisplay, 640);
	KUNIT_EXPECT_EQ(test, preferred->vdisplay, 480);
	KUNIT_EXPECT_EQ(test, preferred->clock, 25200);
}

/*
 * Test that the drm_hdmi_connector_mode_valid() will not mark any modes as
 * valid if .tmds_char_rate_valid() rejects all of them. Pass a correct EDID
 * and verify that there is no preferred mode and no modes were set for the
 * connector.
 */
static void drm_test_check_mode_valid_reject(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector *conn;
	struct drm_display_mode *preferred;
	unsigned char no_edid[] = {};
	int ret;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
					BIT(HDMI_COLORSPACE_RGB),
					8,
					&reject_connector_hdmi_funcs,
					no_edid);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;

	/* should reject all modes */
	ret = set_connector_edid(test, conn,
				 test_edid_hdmi_1080p_rgb_max_200mhz,
				 ARRAY_SIZE(test_edid_hdmi_1080p_rgb_max_200mhz));
	KUNIT_ASSERT_EQ(test, ret, 0);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NULL(test, preferred);
}

/*
 * Test that the drm_hdmi_connector_mode_valid() will reject modes that don't
 * pass the info.max_tmds_clock filter. Pass crafted EDID and verify that
 * high-rate modes are filtered.
 */
static void drm_test_check_mode_valid_reject_max_clock(struct kunit *test)
{
	struct drm_atomic_helper_connector_hdmi_priv *priv;
	struct drm_connector *conn;
	struct drm_display_mode *preferred;

	priv = drm_kunit_helper_connector_hdmi_init_with_edid_funcs(test,
				BIT(HDMI_COLORSPACE_RGB),
				8,
				&dummy_connector_hdmi_funcs,
				test_edid_hdmi_1080p_rgb_max_100mhz);
	KUNIT_ASSERT_NOT_NULL(test, priv);

	conn = &priv->connector;
	KUNIT_ASSERT_EQ(test, conn->display_info.max_tmds_clock, 100 * 1000);

	preferred = find_preferred_mode(conn);
	KUNIT_ASSERT_NOT_NULL(test, preferred);
	KUNIT_EXPECT_EQ(test, preferred->hdisplay, 640);
	KUNIT_EXPECT_EQ(test, preferred->vdisplay, 480);
	KUNIT_EXPECT_EQ(test, preferred->clock, 25200);
}

static struct kunit_case drm_atomic_helper_connector_hdmi_mode_valid_tests[] = {
	KUNIT_CASE(drm_test_check_mode_valid),
	KUNIT_CASE(drm_test_check_mode_valid_reject),
	KUNIT_CASE(drm_test_check_mode_valid_reject_rate),
	KUNIT_CASE(drm_test_check_mode_valid_reject_max_clock),
	{ }
};

static struct kunit_suite drm_atomic_helper_connector_hdmi_mode_valid_test_suite = {
	.name		= "drm_atomic_helper_connector_hdmi_mode_valid",
	.test_cases	= drm_atomic_helper_connector_hdmi_mode_valid_tests,
};

kunit_test_suites(
	&drm_atomic_helper_connector_hdmi_check_test_suite,
	&drm_atomic_helper_connector_hdmi_reset_test_suite,
	&drm_atomic_helper_connector_hdmi_mode_valid_test_suite,
);

MODULE_AUTHOR("Maxime Ripard <mripard@kernel.org>");
MODULE_DESCRIPTION("Kunit test for drm_hdmi_state_helper functions");
MODULE_LICENSE("GPL");
