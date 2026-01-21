#include <string.h>
#include <picoquic_internal.h>

int slipstream_take_stateless_packet(picoquic_quic_t* quic,
                                     uint8_t* out_bytes,
                                     size_t out_capacity,
                                     size_t* out_len) {
    if (out_len == NULL || out_bytes == NULL) {
        return -1;
    }

    picoquic_stateless_packet_t* sp = picoquic_dequeue_stateless_packet(quic);
    if (sp == NULL) {
        return 0;
    }

    if (sp->length > out_capacity) {
        picoquic_delete_stateless_packet(sp);
        return -1;
    }

    memcpy(out_bytes, sp->bytes, sp->length);
    *out_len = sp->length;
    picoquic_delete_stateless_packet(sp);
    return 1;
}
