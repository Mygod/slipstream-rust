#include <string.h>
#include <picoquic_internal.h>

int slipstream_take_stateless_packet_for_cid(picoquic_quic_t* quic,
                                             const uint8_t* packet,
                                             size_t packet_len,
                                             uint8_t* out_bytes,
                                             size_t out_capacity,
                                             size_t* out_len) {
    if (out_len == NULL || out_bytes == NULL || packet == NULL) {
        return -1;
    }

    picoquic_packet_header ph;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_storage dummy_addr;
    memset(&dummy_addr, 0, sizeof(dummy_addr));
    if (picoquic_parse_packet_header(
            quic, packet, packet_len, (struct sockaddr*)&dummy_addr, &ph, &cnx, 1) != 0) {
        return 0;
    }

    picoquic_stateless_packet_t* prev = NULL;
    picoquic_stateless_packet_t* sp = quic->pending_stateless_packet;
    while (sp != NULL) {
        if (sp->initial_cid.id_len == ph.dest_cnx_id.id_len &&
            memcmp(sp->initial_cid.id, ph.dest_cnx_id.id, ph.dest_cnx_id.id_len) == 0) {
            if (sp->length > out_capacity) {
                return -1;
            }
            memcpy(out_bytes, sp->bytes, sp->length);
            *out_len = sp->length;
            if (prev == NULL) {
                quic->pending_stateless_packet = sp->next_packet;
            } else {
                prev->next_packet = sp->next_packet;
            }
            picoquic_delete_stateless_packet(sp);
            return 1;
        }
        prev = sp;
        sp = sp->next_packet;
    }

    return 0;
}
