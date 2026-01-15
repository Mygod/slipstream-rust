#include <stdint.h>

#include <picoquic_internal.h>

typedef enum {
    slipstream_path_mode_unknown = 0,
    slipstream_path_mode_recursive = 1,
    slipstream_path_mode_authoritative = 2,
} slipstream_path_mode_t;

static slipstream_path_mode_t slipstream_default_path_mode = slipstream_path_mode_recursive;
static picoquic_congestion_algorithm_t const* slipstream_cc_override = NULL;

static picoquic_congestion_algorithm_t const* slipstream_select_cc(picoquic_path_t* path_x)
{
    if (slipstream_cc_override != NULL) {
        return slipstream_cc_override;
    }

    slipstream_path_mode_t mode = (slipstream_path_mode_t)path_x->slipstream_path_mode;
    if (mode == slipstream_path_mode_unknown) {
        mode = slipstream_default_path_mode;
    }

    if (mode == slipstream_path_mode_authoritative) {
        return picoquic_bbr_algorithm;
    }
    return picoquic_dcubic_algorithm;
}

static void slipstream_mixed_cc_init(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_init != NULL) {
        alg->alg_init(cnx, path_x, current_time);
    }
}

static void slipstream_mixed_cc_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t* ack_state,
    uint64_t current_time)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_notify != NULL) {
        alg->alg_notify(cnx, path_x, notification, ack_state, current_time);
    }
}

static void slipstream_mixed_cc_delete(picoquic_path_t* path_x)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_delete != NULL) {
        alg->alg_delete(path_x);
    }
}

static void slipstream_mixed_cc_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_observe != NULL) {
        alg->alg_observe(path_x, cc_state, cc_param);
        return;
    }
    *cc_state = 0;
    *cc_param = 0;
}

#define picoquic_slipstream_mixed_cc_ID "slipstream_mixed"
#define PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_MIXED 11

picoquic_congestion_algorithm_t slipstream_mixed_cc_algorithm_struct = {
    picoquic_slipstream_mixed_cc_ID, PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_MIXED,
    slipstream_mixed_cc_init,
    slipstream_mixed_cc_notify,
    slipstream_mixed_cc_delete,
    slipstream_mixed_cc_observe
};

picoquic_congestion_algorithm_t* slipstream_mixed_cc_algorithm = &slipstream_mixed_cc_algorithm_struct;

void slipstream_set_cc_override(const char* alg_name)
{
    if (alg_name == NULL) {
        slipstream_cc_override = NULL;
        return;
    }
    picoquic_congestion_algorithm_t const* alg = picoquic_get_congestion_algorithm(alg_name);
    slipstream_cc_override = alg;
}

void slipstream_set_default_path_mode(int mode)
{
    if (mode == slipstream_path_mode_authoritative || mode == slipstream_path_mode_recursive) {
        slipstream_default_path_mode = (slipstream_path_mode_t)mode;
    } else {
        slipstream_default_path_mode = slipstream_path_mode_recursive;
    }
}

void slipstream_set_path_mode(picoquic_cnx_t* cnx, int path_id, int mode)
{
    if (cnx == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return;
    }
    if (mode != slipstream_path_mode_authoritative && mode != slipstream_path_mode_recursive) {
        mode = slipstream_path_mode_recursive;
    }
    cnx->path[path_id]->slipstream_path_mode = (uint8_t)mode;
}

void slipstream_set_path_ack_delay(picoquic_cnx_t* cnx, int path_id, int disable)
{
    if (cnx == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return;
    }
    cnx->path[path_id]->slipstream_no_ack_delay = (disable != 0) ? 1 : 0;
}

int slipstream_get_path_quality(picoquic_cnx_t* cnx, int path_id, picoquic_path_quality_t* quality)
{
    if (cnx == NULL || quality == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return -1;
    }

    picoquic_path_t* path_x = cnx->path[path_id];
    picoquic_refresh_path_quality_thresholds(path_x);
    quality->cwin = path_x->cwin;
    quality->rtt = path_x->smoothed_rtt;
    quality->rtt_sample = path_x->rtt_sample;
    quality->rtt_min = path_x->rtt_min;
    quality->rtt_max = path_x->rtt_max;
    quality->rtt_variant = path_x->rtt_variant;
    quality->pacing_rate = path_x->pacing.rate;
    quality->receive_rate_estimate = path_x->receive_rate_estimate;
    quality->sent = picoquic_get_sequence_number(path_x->cnx, path_x, picoquic_packet_context_application);
    quality->lost = path_x->nb_losses_found;
    quality->timer_losses = path_x->nb_timer_losses;
    quality->spurious_losses = path_x->nb_spurious;
    quality->max_spurious_rtt = path_x->max_spurious_rtt;
    quality->max_reorder_delay = path_x->max_reorder_delay;
    quality->max_reorder_gap = path_x->max_reorder_gap;
    quality->bytes_in_transit = path_x->bytes_in_transit;
    return 0;
}
