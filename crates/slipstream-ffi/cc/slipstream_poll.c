#include "picoquic_internal.h"

void slipstream_request_poll(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return;
    }
    cnx->is_poll_requested = 1;
}

int slipstream_is_flow_blocked(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return 0;
    }
    return (cnx->flow_blocked || cnx->stream_blocked) ? 1 : 0;
}

int slipstream_has_ready_stream(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return 0;
    }
    return picoquic_find_ready_stream(cnx) != NULL ? 1 : 0;
}

void slipstream_disable_ack_delay(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return;
    }
    cnx->no_ack_delay = 1;
}
