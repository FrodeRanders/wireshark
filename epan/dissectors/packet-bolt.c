/* packet-bolt.c
 * Routines for Bolt protocol (Neo4j) dissection
 * Copyright 2020 Frode Randers <frode.randers@forsakringskassan.se>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The protocol is divided into two layers; the transport Layer and the messaging layer.
 * Protocol references:
 * https://boltprotocol.org
 *
 */

#include "config.h"
#include <epan/packet.h>

void proto_reg_handoff_bolt(void);

void proto_register_bolt(void);


#define BOLT_PORT 7687

#define MESSAGE_HEADER_SIZE 2

static int proto_bolt = -1;

static int hf_bolt_protocol_version = -1;
static int hf_bolt_chunk_size = -1;
static int hf_bolt_pdu_type = -1;

static gint ett_bolt = -1;


enum bolt_packets {
    // Transport layer version negotiation
    VERSION_REQUEST = 0x60,
    VERSION_RESPONSE = 0x00,

    // Request messages from client to server
    HELLO = 0x01,
    GOODBYE = 0x02,
    RESET = 0x0F,
    RUN = 0x10,
    BEGIN = 0x11,
    COMMIT = 0x12,
    ROLLBACK = 0x13,
    DISCARD = 0x2F,
    PULL = 0x3F,

    // Summary and detail messages from server to client
    SUCCESS = 0x70, // summary message
    RECORD = 0x71,  // detail message
    IGNORED = 0x7E, // summary message
    FAILURE = 0x7F, // summary message
};

static const value_string packettypenames[] = {
        {VERSION_REQUEST, "VERSION_REQUEST"},
        {VERSION_RESPONSE, "VERSION_RESPONSE"},
        {HELLO, "HELLO"},
        {GOODBYE, "GOODBYE"},
        {RESET, "RESET"},
        {RUN, "RUN"},
        {BEGIN, "BEGIN"},
        {COMMIT, "COMMIT"},
        {ROLLBACK, "ROLLBACK"},
        {DISCARD, "DISCARD"},
        {PULL, "PULL"},
        {SUCCESS, "SUCCESS"},
        { RECORD, "RECORD" },
        { IGNORED, "IGNORED" },
        { FAILURE, "FAILURE" },
        { 0, NULL },
};

static int
dissect_bolt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BOLT");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_bolt, tvb, 0, -1, ENC_NA);

    proto_tree *bolt_tree = proto_item_add_subtree(ti, ett_bolt);

    guint captured_length = tvb_captured_length(tvb);
    if (captured_length < 4) {
        return captured_length;
    }

    if (4 == captured_length) {
        // version negotiation response
        // <uint32:version>
        // E.g.
        //   00 00 00 04 -> agreed on version 4
        //   00 00 00 00 -> no agreement on version
        // we will pick the first byte as type specifier, sorta
        proto_tree_add_item(bolt_tree, hf_bolt_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(bolt_tree, hf_bolt_protocol_version, tvb, 0, 4, ENC_BIG_ENDIAN);
    }
    else {
        // First check if we are in transport layer mode, negotiating versions
        // before we check message layer variants
        guint32 word = tvb_get_ntohl(tvb, 0);
        if (word == 0x6060B017) {  // Go Go Bolt!
            // <uint32:0x6060B017><uint32:version><uint32:version><uint32:version><uint32:version>
            // we will pick the first byte as type specifier, sorta
            proto_tree_add_item(bolt_tree, hf_bolt_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bolt_tree, hf_bolt_protocol_version, tvb, 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(bolt_tree, hf_bolt_protocol_version, tvb, 8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(bolt_tree, hf_bolt_protocol_version, tvb, 12, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(bolt_tree, hf_bolt_protocol_version, tvb, 16, 4, ENC_BIG_ENDIAN);
        }
        else {
            // <uint16:chunk size><uint8:struct type><uint8:signature>...
            proto_tree_add_item(bolt_tree, hf_bolt_chunk_size, tvb, 0, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(bolt_tree, hf_bolt_pdu_type, tvb, 3, 1, ENC_BIG_ENDIAN);
        }
    }

    return captured_length;
}

void
proto_register_bolt(void) {
    static hf_register_info hf[] = {
            {&hf_bolt_protocol_version, {"Protocol version", "bolt.protocol.version", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
            {&hf_bolt_chunk_size, {"Chunk size", "bolt.chunk.size", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
            {&hf_bolt_pdu_type, {"PDU type", "bolt.message.type", FT_UINT8, BASE_HEX, VALS(packettypenames), 0x0, NULL, HFILL}}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
            &ett_bolt
    };

    proto_bolt = proto_register_protocol("Bolt protocol", "Bolt", "bolt");
    proto_register_field_array(proto_bolt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bolt(void) {
    static dissector_handle_t bolt_handle;

    bolt_handle = create_dissector_handle(dissect_bolt, proto_bolt);
    dissector_add_uint("tcp.port", BOLT_PORT, bolt_handle);
}

