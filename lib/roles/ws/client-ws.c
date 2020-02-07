/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include <core/private.h>

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))

/*
 * In-place str to lower case
 */

static void
strtolower(char *s)
{
	while (*s) {
#ifdef LWS_PLAT_OPTEE
		int tolower_optee(int c);
		*s = tolower_optee((int)*s);
#else
		*s = tolower((int)*s);
#endif
		s++;
	}
}

int
lws_create_client_ws_object(const struct lws_client_connect_info *i,
			    struct lws *wsi)
{
	int v = SPEC_LATEST_SUPPORTED;

	/* allocate the ws struct for the wsi */
	wsi->ws = lws_zalloc(sizeof(*wsi->ws), "client ws struct");
	if (!wsi->ws) {
		lwsl_notice("OOM\n");
		return 1;
	}

	/* -1 means just use latest supported */
	if (i->ietf_version_or_minus_one != -1 &&
	    i->ietf_version_or_minus_one)
		v = i->ietf_version_or_minus_one;

	wsi->ws->ietf_spec_revision = v;

	return 0;
}

#if !defined(LWS_NO_CLIENT)
static inline int
lws_ws_client_rx_sm(struct lws *wsi, unsigned char *buf, size_t len)
{
    int callback_action = LWS_CALLBACK_CLIENT_RECEIVE;
    int handled, m;
    unsigned short close_code;
    struct lws_tokens ebuf;
    unsigned char *pp;
#if !defined(LWS_WITHOUT_EXTENSIONS)
    int rx_draining_ext = 0, n;
#endif

    int parsed = 1;
    ebuf.token = NULL;
    ebuf.len = 0;

#if !defined(LWS_WITHOUT_EXTENSIONS)
    if (wsi->ws->rx_draining_ext) {
		assert(!*buf);

		lws_remove_wsi_from_draining_ext_list(wsi);
		rx_draining_ext = 1;
		lwsl_debug("%s: doing draining flow\n", __func__);

		goto drain_extension;
	}
#endif

    if (wsi->socket_is_permanently_unusable)
        return -1;

    switch (wsi->lws_rx_parse_state) {
        case LWS_RXPS_NEW:
            /* control frames (PING) may interrupt checkable sequences */
            wsi->ws->defeat_check_utf8 = 0;

            switch (wsi->ws->ietf_spec_revision) {
                case 13:
                    wsi->ws->opcode = *buf & 0xf;
                    /* revisit if an extension wants them... */
                    switch (wsi->ws->opcode) {
                        case LWSWSOPC_TEXT_FRAME:
                            wsi->ws->rsv_first_msg = (*buf & 0x70);
                            wsi->ws->continuation_possible = 1;
                            wsi->ws->check_utf8 = lws_check_opt(
                                    wsi->context->options,
                                    LWS_SERVER_OPTION_VALIDATE_UTF8);
                            wsi->ws->utf8 = 0;
                            wsi->ws->first_fragment = 1;
                            break;
                        case LWSWSOPC_BINARY_FRAME:
                            wsi->ws->rsv_first_msg = (*buf & 0x70);
                            wsi->ws->check_utf8 = 0;
                            wsi->ws->continuation_possible = 1;
                            wsi->ws->first_fragment = 1;
                            break;
                        case LWSWSOPC_CONTINUATION:
                            if (!wsi->ws->continuation_possible) {
                                lwsl_info("disordered continuation\n");
                                return -1;
                            }
                            wsi->ws->first_fragment = 0;
                            break;
                        case LWSWSOPC_CLOSE:
                            wsi->ws->check_utf8 = 0;
                            wsi->ws->utf8 = 0;
                            break;
                        case 3:
                        case 4:
                        case 5:
                        case 6:
                        case 7:
                        case 0xb:
                        case 0xc:
                        case 0xd:
                        case 0xe:
                        case 0xf:
                            lwsl_info("illegal opcode\n");
                            return -1;
                        default:
                            wsi->ws->defeat_check_utf8 = 1;
                            break;
                    }
                    wsi->ws->rsv = (*buf & 0x70);
                    /* revisit if an extension wants them... */
                    if (
#if !defined(LWS_WITHOUT_EXTENSIONS)
                            !wsi->ws->count_act_ext &&
#endif
                            wsi->ws->rsv) {
                        lwsl_info("illegal rsv bits set\n");
                        return -1;
                    }
                    wsi->ws->final = !!((*buf >> 7) & 1);
                    lwsl_ext("%s:    This RX frame Final %d\n", __func__,
                             wsi->ws->final);

                    if (wsi->ws->owed_a_fin &&
                        (wsi->ws->opcode == LWSWSOPC_TEXT_FRAME ||
                         wsi->ws->opcode == LWSWSOPC_BINARY_FRAME)) {
                        lwsl_info("hey you owed us a FIN\n");
                        return -1;
                    }
                    if ((!(wsi->ws->opcode & 8)) && wsi->ws->final) {
                        wsi->ws->continuation_possible = 0;
                        wsi->ws->owed_a_fin = 0;
                    }

                    if ((wsi->ws->opcode & 8) && !wsi->ws->final) {
                        lwsl_info("control msg can't be fragmented\n");
                        return -1;
                    }
                    if (!wsi->ws->final)
                        wsi->ws->owed_a_fin = 1;

                    switch (wsi->ws->opcode) {
                        case LWSWSOPC_TEXT_FRAME:
                        case LWSWSOPC_BINARY_FRAME:
                            wsi->ws->frame_is_binary = wsi->ws->opcode ==
                                                       LWSWSOPC_BINARY_FRAME;
                            break;
                    }
                    wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
                    break;

                default:
                    lwsl_err("unknown spec version %02d\n",
                             wsi->ws->ietf_spec_revision);
                    break;
            }
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN:

            wsi->ws->this_frame_masked = !!(*buf & 0x80);

            switch (*buf & 0x7f) {
                case 126:
                    /* control frames are not allowed to have big lengths */
                    if (wsi->ws->opcode & 8)
                        goto illegal_ctl_length;
                    wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
                    break;
                case 127:
                    /* control frames are not allowed to have big lengths */
                    if (wsi->ws->opcode & 8)
                        goto illegal_ctl_length;
                    wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
                    break;
                default:
                    wsi->ws->rx_packet_length = *buf & 0x7f;
                    if (wsi->ws->this_frame_masked)
                        wsi->lws_rx_parse_state =
                                LWS_RXPS_07_COLLECT_FRAME_KEY_1;
                    else {
                        if (wsi->ws->rx_packet_length) {
                            wsi->lws_rx_parse_state =
                                    LWS_RXPS_WS_FRAME_PAYLOAD;
                        } else {
                            wsi->lws_rx_parse_state = LWS_RXPS_NEW;
                            ebuf.token = &wsi->ws->rx_ubuf[LWS_PRE];
                            ebuf.len = wsi->ws->rx_ubuf_head;
                            goto spill;
                        }
                    }
                    break;
            }
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN16_2:
            wsi->ws->rx_packet_length = *buf << 8;
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN16_1:
            wsi->ws->rx_packet_length |= *buf;
            if (wsi->ws->this_frame_masked)
                wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_1;
            else {
                if (wsi->ws->rx_packet_length)
                    wsi->lws_rx_parse_state =
                            LWS_RXPS_WS_FRAME_PAYLOAD;
                else {
                    wsi->lws_rx_parse_state = LWS_RXPS_NEW;
                    ebuf.token = &wsi->ws->rx_ubuf[LWS_PRE];
                    ebuf.len = wsi->ws->rx_ubuf_head;
                    goto spill;
                }
            }
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_8:
            if (*buf & 0x80) {
                lwsl_warn("b63 of length must be zero\n");
                /* kill the connection */
                return -1;
            }
#if defined __LP64__
            wsi->ws->rx_packet_length = ((size_t)*buf) << 56;
#else
            wsi->ws->rx_packet_length = 0;
#endif
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
            wsi->ws->rx_packet_length |= ((size_t)*buf) << 48;
#endif
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
            wsi->ws->rx_packet_length |= ((size_t)*buf) << 40;
#endif
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
            wsi->ws->rx_packet_length |= ((size_t)*buf) << 32;
#endif
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_4:
            wsi->ws->rx_packet_length |= ((size_t)*buf) << 24;
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_3:
            wsi->ws->rx_packet_length |= ((size_t)*buf) << 16;
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_2:
            wsi->ws->rx_packet_length |= ((size_t)*buf) << 8;
            wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
            break;

        case LWS_RXPS_04_FRAME_HDR_LEN64_1:
            wsi->ws->rx_packet_length |= (size_t)*buf;
            if (wsi->ws->this_frame_masked)
                wsi->lws_rx_parse_state =
                        LWS_RXPS_07_COLLECT_FRAME_KEY_1;
            else {
                if (wsi->ws->rx_packet_length)
                    wsi->lws_rx_parse_state =
                            LWS_RXPS_WS_FRAME_PAYLOAD;
                else {
                    wsi->lws_rx_parse_state = LWS_RXPS_NEW;
                    ebuf.token = &wsi->ws->rx_ubuf[LWS_PRE];
                    ebuf.len = wsi->ws->rx_ubuf_head;
                    goto spill;
                }
            }
            break;

        case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
            wsi->ws->mask[0] = *buf;
            if (*buf)
                wsi->ws->all_zero_nonce = 0;
            wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
            break;

        case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
            wsi->ws->mask[1] = *buf;
            if (*buf)
                wsi->ws->all_zero_nonce = 0;
            wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
            break;

        case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
            wsi->ws->mask[2] = *buf;
            if (*buf)
                wsi->ws->all_zero_nonce = 0;
            wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
            break;

        case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
            wsi->ws->mask[3] = *buf;
            if (*buf)
                wsi->ws->all_zero_nonce = 0;

            if (wsi->ws->rx_packet_length)
                wsi->lws_rx_parse_state =
                        LWS_RXPS_WS_FRAME_PAYLOAD;
            else {
                wsi->lws_rx_parse_state = LWS_RXPS_NEW;
                ebuf.token = &wsi->ws->rx_ubuf[LWS_PRE];
                ebuf.len = wsi->ws->rx_ubuf_head;
                goto spill;
            }
            break;

        case LWS_RXPS_WS_FRAME_PAYLOAD:

            assert(wsi->ws->rx_ubuf);
#if !defined(LWS_WITHOUT_EXTENSIONS)
        if (wsi->ws->rx_draining_ext)
			goto drain_extension;
#endif

            /* bulk read */
            if (wsi->ws->rx_packet_length <= len &&
                (wsi->ws->opcode == LWSWSOPC_TEXT_FRAME ||
                 wsi->ws->opcode == LWSWSOPC_BINARY_FRAME ||
                 wsi->ws->opcode == LWSWSOPC_CONTINUATION)) {

                parsed = wsi->ws->rx_packet_length;
                wsi->ws->rx_packet_length = 0;
                wsi->ws->rx_ubuf_head += parsed;
                ebuf.token = (char *) buf;
                ebuf.len = parsed;

            } else {
                parsed = MIN(len, wsi->ws->rx_packet_length);

                int diff;
                if (!wsi->protocol->rx_buffer_size) {
                    diff = wsi->context->pt_serv_buf_size - wsi->ws->rx_ubuf_head;
                } else {
                    diff = wsi->protocol->rx_buffer_size - wsi->ws->rx_ubuf_head;
                }

                parsed = MIN(parsed, diff);
                memcpy(&wsi->ws->rx_ubuf[LWS_PRE + wsi->ws->rx_ubuf_head], buf, parsed);

                wsi->ws->rx_packet_length -= parsed;
                wsi->ws->rx_ubuf_head += parsed;
                ebuf.token = &wsi->ws->rx_ubuf[LWS_PRE];
                ebuf.len = wsi->ws->rx_ubuf_head;
            }

            if (wsi->ws->this_frame_masked && !wsi->ws->all_zero_nonce) {
                for (int i = 0; i < ebuf.len; ++i)
                    ebuf.token[i] = wsi->ws->mask[(wsi->ws->mask_idx++) & 3];
            }

            if (wsi->ws->rx_packet_length == 0) {
                /* spill because we have the whole frame */
                wsi->lws_rx_parse_state = LWS_RXPS_NEW;
            }

            /* spill because we filled our rx buffer */
        spill:

            handled = 0;

            /*
             * is this frame a control packet we should take care of at this
             * layer?  If so service it and hide it from the user callback
             */

            switch (wsi->ws->opcode) {
                case LWSWSOPC_CLOSE:
                    pp = (unsigned char *)&wsi->ws->rx_ubuf[LWS_PRE];
                    if (lws_check_opt(wsi->context->options,
                                      LWS_SERVER_OPTION_VALIDATE_UTF8) &&
                        wsi->ws->rx_ubuf_head > 2 &&
                        lws_check_utf8(&wsi->ws->utf8, pp + 2,
                                       wsi->ws->rx_ubuf_head - 2))
                        goto utf8_fail;

                    /* is this an acknowledgment of our close? */
                    if (lwsi_state(wsi) == LRS_AWAITING_CLOSE_ACK) {
                        /*
                         * fine he has told us he is closing too, let's
                         * finish our close
                         */
                        lwsl_parser("seen server's close ack\n");
                        return -1;
                    }

                    lwsl_parser("client sees server close len = %d\n",
                                wsi->ws->rx_ubuf_head);
                    if (wsi->ws->rx_ubuf_head >= 2) {
                        close_code = (pp[0] << 8) | pp[1];
                        if (close_code < 1000 ||
                            close_code == 1004 ||
                            close_code == 1005 ||
                            close_code == 1006 ||
                            close_code == 1012 ||
                            close_code == 1013 ||
                            close_code == 1014 ||
                            close_code == 1015 ||
                            (close_code >= 1016 && close_code < 3000)
                                ) {
                            pp[0] = (LWS_CLOSE_STATUS_PROTOCOL_ERR >> 8) & 0xff;
                            pp[1] = LWS_CLOSE_STATUS_PROTOCOL_ERR & 0xff;
                        }
                    }
                    if (user_callback_handle_rxflow(
                            wsi->protocol->callback, wsi,
                            LWS_CALLBACK_WS_PEER_INITIATED_CLOSE,
                            wsi->user_space, pp,
                            wsi->ws->rx_ubuf_head))
                        return -1;

                    memcpy(wsi->ws->ping_payload_buf + LWS_PRE, pp,
                           wsi->ws->rx_ubuf_head);
                    wsi->ws->close_in_ping_buffer_len =
                            wsi->ws->rx_ubuf_head;

                    lwsl_info("%s: scheduling return close as ack\n",
                              __func__);
                    __lws_change_pollfd(wsi, LWS_POLLIN, 0);
                    lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_SEND, 3);
                    wsi->waiting_to_send_close_frame = 1;
                    wsi->close_needs_ack = 0;
                    lwsi_set_state(wsi, LRS_WAITING_TO_SEND_CLOSE);
                    lws_callback_on_writable(wsi);
                    handled = 1;
                    break;

                case LWSWSOPC_PING:
                    lwsl_info("received %d byte ping, sending pong\n",
                              wsi->ws->rx_ubuf_head);

                    /* he set a close reason on this guy, ignore PING */
                    if (wsi->ws->close_in_ping_buffer_len)
                        goto ping_drop;

                    if (wsi->ws->ping_pending_flag) {
                        /*
                         * there is already a pending ping payload
                         * we should just log and drop
                         */
                        lwsl_parser("DROP PING since one pending\n");
                        goto ping_drop;
                    }

                    /* control packets can only be < 128 bytes long */
                    if (wsi->ws->rx_ubuf_head > 128 - 3) {
                        lwsl_parser("DROP PING payload too large\n");
                        goto ping_drop;
                    }

                    /* stash the pong payload */
                    memcpy(wsi->ws->ping_payload_buf + LWS_PRE,
                           &wsi->ws->rx_ubuf[LWS_PRE],
                           wsi->ws->rx_ubuf_head);

                    wsi->ws->ping_payload_len = wsi->ws->rx_ubuf_head;
                    wsi->ws->ping_pending_flag = 1;

                    /* get it sent as soon as possible */
                    lws_callback_on_writable(wsi);
                ping_drop:
                    wsi->ws->rx_ubuf_head = 0;
                    handled = 1;
                    break;

                case LWSWSOPC_PONG:
                    lwsl_info("client received pong\n");
                    lwsl_hexdump(&wsi->ws->rx_ubuf[LWS_PRE],
                                 wsi->ws->rx_ubuf_head);

                    if (wsi->pending_timeout ==
                        PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG) {
                        lwsl_info("%p: received expected PONG\n", wsi);
                        lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
                    }

                    /* issue it */
                    callback_action = LWS_CALLBACK_CLIENT_RECEIVE_PONG;
                    break;

                case LWSWSOPC_CONTINUATION:
                case LWSWSOPC_TEXT_FRAME:
                case LWSWSOPC_BINARY_FRAME:
                    break;

                default:
                    /* not handled or failed */
                    lwsl_ext("Unhandled ext opc 0x%x\n", wsi->ws->opcode);
                    wsi->ws->rx_ubuf_head = 0;

                    return -1;
            }

            /*
             * No it's real payload, pass it up to the user callback.
             * It's nicely buffered with the pre-padding taken care of
             * so it can be sent straight out again using lws_write
             */
            if (handled)
                goto already_done;

#if !defined(LWS_WITHOUT_EXTENSIONS)
drain_extension:
		lwsl_ext("%s: passing %d to ext\n", __func__, ebuf.len);

		n = lws_ext_cb_active(wsi, LWS_EXT_CB_PAYLOAD_RX, &ebuf, 0);
		lwsl_ext("Ext RX returned %d\n", n);
		if (n < 0) {
			wsi->socket_is_permanently_unusable = 1;
			return -1;
		}
#endif
            lwsl_debug("post inflate ebuf len %d\n", ebuf.len);

#if !defined(LWS_WITHOUT_EXTENSIONS)
        if (rx_draining_ext && !ebuf.len) {
			lwsl_debug("   --- ending drain on 0 read result\n");
			goto already_done;
		}
#endif

            if (wsi->ws->check_utf8 && !wsi->ws->defeat_check_utf8) {
                if (lws_check_utf8(&wsi->ws->utf8,
                                   (unsigned char *)ebuf.token,
                                   ebuf.len)) {
                    lws_close_reason(wsi,
                                     LWS_CLOSE_STATUS_INVALID_PAYLOAD,
                                     (uint8_t *)"bad utf8", 8);
                    goto utf8_fail;
                }

                /* we are ending partway through utf-8 character? */
                if (!wsi->ws->rx_packet_length && wsi->ws->final &&
                    wsi->ws->utf8
#if !defined(LWS_WITHOUT_EXTENSIONS)
                    && !n
#endif
                        ) {
                    lwsl_info("FINAL utf8 error\n");
                    lws_close_reason(wsi,
                                     LWS_CLOSE_STATUS_INVALID_PAYLOAD,
                                     (uint8_t *)"partial utf8", 12);
                    utf8_fail:
                    lwsl_info("utf8 error\n");
                    lwsl_hexdump_info(ebuf.token, ebuf.len);

                    return -1;
                }
            }

            if (ebuf.len < 0 &&
                callback_action != LWS_CALLBACK_CLIENT_RECEIVE_PONG)
                goto already_done;

            if (!ebuf.token)
                goto already_done;

            if (!wsi->protocol->callback)
                goto already_done;

            if (callback_action == LWS_CALLBACK_CLIENT_RECEIVE_PONG)
                lwsl_info("Client doing pong callback\n");

            if (
                /* coverity says dead code otherwise */
#if !defined(LWS_WITHOUT_EXTENSIONS)
                    n &&
#endif
                    ebuf.len)
                /* extension had more... main loop will come back
                 * we want callback to be done with this set, if so,
                 * because lws_is_final() hides it was final until the
                 * last chunk
                 */
                lws_add_wsi_to_draining_ext_list(wsi);
            else
                lws_remove_wsi_from_draining_ext_list(wsi);

            if (lwsi_state(wsi) == LRS_RETURNED_CLOSE ||
                lwsi_state(wsi) == LRS_WAITING_TO_SEND_CLOSE ||
                lwsi_state(wsi) == LRS_AWAITING_CLOSE_ACK)
                goto already_done;

            m = wsi->protocol->callback(wsi,
                                        (enum lws_callback_reasons)callback_action,
                                        wsi->user_space, ebuf.token, ebuf.len);

            wsi->ws->first_fragment = 0;

            // lwsl_notice("%s: bulk ws rx: input used %d, output %d\n",
            //	__func__, wsi->ws->rx_ubuf_head, ebuf.len);

            /* if user code wants to close, let caller know */
            if (m)
                return -1;

        already_done:
            wsi->ws->rx_ubuf_head = 0;
            break;
        default:
            lwsl_err("client rx illegal state\n");
            return -1;
    }

    return parsed;

    illegal_ctl_length:
    lwsl_warn("Control frame asking for extended length is illegal\n");

    /* kill the connection */
    return -1;
}

int
lws_ws_handshake_client(struct lws *wsi, unsigned char **buf, size_t len)
{
	if ((lwsi_state(wsi) != LRS_WAITING_PROXY_REPLY) &&
	    (lwsi_state(wsi) != LRS_H1C_ISSUE_HANDSHAKE) &&
	    (lwsi_state(wsi) != LRS_WAITING_SERVER_REPLY) &&
	    !lwsi_role_client(wsi))
		return 0;

	// lwsl_notice("%s: hs client gets %d in\n", __func__, (int)len);

	while (len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (lws_is_flowcontrolled(wsi)) {
			//lwsl_notice("%s: caching %ld\n", __func__, (long)len);
			lws_rxflow_cache(wsi, *buf, 0, (int)len);
			*buf += len;
			return 0;
		}
#if !defined(LWS_WITHOUT_EXTENSIONS)
		if (wsi->ws->rx_draining_ext) {
			int m;

			//lwsl_notice("%s: draining ext\n", __func__);
			if (lwsi_role_client(wsi))
				m = lws_ws_client_rx_sm(wsi, 0);
			else
				m = lws_ws_rx_sm(wsi, 0, 0);
			if (m < 0)
				return -1;
			continue;
		}
#endif
		/* caller will account for buflist usage */

        int res = lws_ws_client_rx_sm(wsi, *buf, len);
        if (res == -1) {
            lwsl_notice("%s: client_rx_sm exited, DROPPING %d\n",
                        __func__, (int)len);
            return -1;
        }

        *buf += res;
        len -= res;
	}
	// lwsl_notice("%s: finished with %ld\n", __func__, (long)len);

	return 0;
}
#endif

char *
lws_generate_client_ws_handshake(struct lws *wsi, char *p, const char *conn1)
{
	char buf[128], hash[20], key_b64[40];
	int n;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	const struct lws_extension *ext;
	int ext_count = 0;
#endif

	/*
	 * create the random key
	 */
	n = lws_get_random(wsi->context, hash, 16);
	if (n != 16) {
		lwsl_err("Unable to read from random dev %s\n",
			 SYSTEM_RANDOM_FILEPATH);
		return NULL;
	}

	lws_b64_encode_string(hash, 16, key_b64, sizeof(key_b64));

	p += sprintf(p, "Upgrade: websocket\x0d\x0a"
			"Connection: %sUpgrade\x0d\x0a"
			"Sec-WebSocket-Key: ", conn1);
	strcpy(p, key_b64);
	p += strlen(key_b64);
	p += sprintf(p, "\x0d\x0a");
	if (lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS))
		p += sprintf(p, "Sec-WebSocket-Protocol: %s\x0d\x0a",
		     lws_hdr_simple_ptr(wsi,
				     _WSI_TOKEN_CLIENT_SENT_PROTOCOLS));

	/* tell the server what extensions we could support */

#if !defined(LWS_WITHOUT_EXTENSIONS)
	ext = wsi->vhost->ws.extensions;
	while (ext && ext->callback) {

		n = wsi->vhost->protocols[0].callback(wsi,
			LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED,
				wsi->user_space, (char *)ext->name, 0);

		/*
		 * zero return from callback means go ahead and allow
		 * the extension, it's what we get if the callback is
		 * unhandled
		 */

		if (n) {
			ext++;
			continue;
		}

		/* apply it */

		if (ext_count)
			*p++ = ',';
		else
			p += sprintf(p, "Sec-WebSocket-Extensions: ");
		p += sprintf(p, "%s", ext->client_offer);
		ext_count++;

		ext++;
	}
	if (ext_count)
		p += sprintf(p, "\x0d\x0a");
#endif

	if (wsi->ws->ietf_spec_revision)
		p += sprintf(p, "Sec-WebSocket-Version: %d\x0d\x0a",
			     wsi->ws->ietf_spec_revision);

	/* prepare the expected server accept response */

	key_b64[39] = '\0'; /* enforce composed length below buf sizeof */
	n = sprintf(buf, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
			  key_b64);

	lws_SHA1((unsigned char *)buf, n, (unsigned char *)hash);

	lws_b64_encode_string(hash, 20,
		  wsi->http.ah->initial_handshake_hash_base64,
		  sizeof(wsi->http.ah->initial_handshake_hash_base64));

	return p;
}

int
lws_client_ws_upgrade(struct lws *wsi, const char **cce)
{
	struct lws_context *context = wsi->context;
	struct lws_tokenize ts;
	int n, len, okay = 0;
	lws_tokenize_elem e;
	char *p, buf[64];
	const char *pc;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *sb = (char *)&pt->serv_buf[0];
	const struct lws_ext_options *opts;
	const struct lws_extension *ext;
	char ext_name[128];
	const char *c, *a;
	int more = 1;
	char ignore;
#endif

	if (wsi->client_h2_substream) {/* !!! client ws-over-h2 not there yet */
		lwsl_warn("%s: client ws-over-h2 upgrade not supported yet\n",
			  __func__);
		*cce = "HS: h2 / ws upgrade unsupported";
		goto bail3;
	}

	if (wsi->http.ah->http_response == 401) {
		lwsl_warn(
		       "lws_client_handshake: got bad HTTP response '%d'\n",
		       wsi->http.ah->http_response);
		*cce = "HS: ws upgrade unauthorized";
		goto bail3;
	}

	if (wsi->http.ah->http_response != 101) {
		lwsl_warn(
		       "lws_client_handshake: got bad HTTP response '%d'\n",
		       wsi->http.ah->http_response);
		*cce = "HS: ws upgrade response not 101";
		goto bail3;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_ACCEPT) == 0) {
		lwsl_info("no ACCEPT\n");
		*cce = "HS: ACCEPT missing";
		goto bail3;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE);
	if (!p) {
		lwsl_info("no UPGRADE\n");
		*cce = "HS: UPGRADE missing";
		goto bail3;
	}
	strtolower(p);
	if (strcmp(p, "websocket")) {
		lwsl_warn(
		      "lws_client_handshake: got bad Upgrade header '%s'\n", p);
		*cce = "HS: Upgrade to something other than websocket";
		goto bail3;
	}

	/* connection: must have "upgrade" */

	lws_tokenize_init(&ts, buf, LWS_TOKENIZE_F_COMMA_SEP_LIST |
				    LWS_TOKENIZE_F_MINUS_NONTERM);
	ts.len = lws_hdr_copy(wsi, buf, sizeof(buf) - 1, WSI_TOKEN_CONNECTION);
	if (ts.len <= 0) /* won't fit, or absent */
		goto bad_conn_format;

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (!strcasecmp(ts.token, "upgrade"))
				e = LWS_TOKZE_ENDED;
			break;

		case LWS_TOKZE_DELIMITER:
			break;

		default: /* includes ENDED */
bad_conn_format:
			*cce = "HS: UPGRADE malformed";
			goto bail3;
		}
	} while (e > 0);

	pc = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS);
	if (!pc) {
		lwsl_parser("lws_client_int_s_hs: no protocol list\n");
	} else
		lwsl_parser("lws_client_int_s_hs: protocol list '%s'\n", pc);

	/*
	 * confirm the protocol the server wants to talk was in the list
	 * of protocols we offered
	 */

	len = lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL);
	if (!len) {
		lwsl_info("%s: WSI_TOKEN_PROTOCOL is null\n", __func__);
		/*
		 * no protocol name to work from,
		 * default to first protocol
		 */
		n = 0;
		wsi->protocol = &wsi->vhost->protocols[0];
		goto check_extensions;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL);
	len = (int)strlen(p);

	while (pc && *pc && !okay) {
		if (!strncmp(pc, p, len) &&
		    (pc[len] == ',' || pc[len] == '\0')) {
			okay = 1;
			continue;
		}
		while (*pc && *pc++ != ',')
			;
		while (*pc == ' ')
			pc++;
	}

	if (!okay) {
		lwsl_info("%s: got bad protocol %s\n", __func__, p);
		*cce = "HS: PROTOCOL malformed";
		goto bail2;
	}

	/*
	 * identify the selected protocol struct and set it
	 */
	n = 0;
	/* keep client connection pre-bound protocol */
	if (!lwsi_role_client(wsi))
		wsi->protocol = NULL;

	while (wsi->vhost->protocols[n].callback) {
		if (!wsi->protocol &&
		    strcmp(p, wsi->vhost->protocols[n].name) == 0) {
			wsi->protocol = &wsi->vhost->protocols[n];
			break;
		}
		n++;
	}

	if (!wsi->vhost->protocols[n].callback) { /* no match */
		/* if server, that's already fatal */
		if (!lwsi_role_client(wsi)) {
			lwsl_info("%s: fail protocol %s\n", __func__, p);
			*cce = "HS: Cannot match protocol";
			goto bail2;
		}

		/* for client, find the index of our pre-bound protocol */

		n = 0;
		while (wsi->vhost->protocols[n].callback) {
			if (wsi->protocol && strcmp(wsi->protocol->name,
				   wsi->vhost->protocols[n].name) == 0) {
				wsi->protocol = &wsi->vhost->protocols[n];
				break;
			}
			n++;
		}

		if (!wsi->vhost->protocols[n].callback) {
			if (wsi->protocol)
				lwsl_err("Failed to match protocol %s\n",
						wsi->protocol->name);
			else
				lwsl_err("No protocol on client\n");
			goto bail2;
		}
	}

	lwsl_debug("Selected protocol %s\n", wsi->protocol->name);

check_extensions:
	/*
	 * stitch protocol choice into the vh protocol linked list
	 * We always insert ourselves at the start of the list
	 *
	 * X <-> B
	 * X <-> pAn <-> pB
	 */

	lws_same_vh_protocol_insert(wsi, n);

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* instantiate the accepted extensions */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_EXTENSIONS)) {
		lwsl_ext("no client extensions allowed by server\n");
		goto check_accept;
	}

	/*
	 * break down the list of server accepted extensions
	 * and go through matching them or identifying bogons
	 */

	if (lws_hdr_copy(wsi, sb, context->pt_serv_buf_size,
			 WSI_TOKEN_EXTENSIONS) < 0) {
		lwsl_warn("ext list from server failed to copy\n");
		*cce = "HS: EXT: list too big";
		goto bail2;
	}

	c = sb;
	n = 0;
	ignore = 0;
	a = NULL;
	while (more) {

		if (*c && (*c != ',' && *c != '\t')) {
			if (*c == ';') {
				ignore = 1;
				if (!a)
					a = c + 1;
			}
			if (ignore || *c == ' ') {
				c++;
				continue;
			}

			ext_name[n] = *c++;
			if (n < (int)sizeof(ext_name) - 1)
				n++;
			continue;
		}
		ext_name[n] = '\0';
		ignore = 0;
		if (!*c)
			more = 0;
		else {
			c++;
			if (!n)
				continue;
		}

		/* check we actually support it */

		lwsl_notice("checking client ext %s\n", ext_name);

		n = 0;
		ext = wsi->vhost->ws.extensions;
		while (ext && ext->callback) {
			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			n = 1;
			lwsl_notice("instantiating client ext %s\n", ext_name);

			/* instantiate the extension on this conn */

			wsi->ws->active_extensions[wsi->ws->count_act_ext] = ext;

			/* allow him to construct his ext instance */

			if (ext->callback(lws_get_context(wsi), ext, wsi,
				   LWS_EXT_CB_CLIENT_CONSTRUCT,
				   (void *)&wsi->ws->act_ext_user[
				                        wsi->ws->count_act_ext],
				   (void *)&opts, 0)) {
				lwsl_info(" ext %s failed construction\n",
					  ext_name);
				ext++;
				continue;
			}

			/*
			 * allow the user code to override ext defaults if it
			 * wants to
			 */
			ext_name[0] = '\0';
			if (user_callback_handle_rxflow(wsi->protocol->callback,
					wsi, LWS_CALLBACK_WS_EXT_DEFAULTS,
					(char *)ext->name, ext_name,
					sizeof(ext_name))) {
				*cce = "HS: EXT: failed setting defaults";
				goto bail2;
			}

			if (ext_name[0] &&
			    lws_ext_parse_options(ext, wsi,
					          wsi->ws->act_ext_user[
						        wsi->ws->count_act_ext],
					          opts, ext_name,
						  (int)strlen(ext_name))) {
				lwsl_err("%s: unable to parse user defaults '%s'",
					 __func__, ext_name);
				*cce = "HS: EXT: failed parsing defaults";
				goto bail2;
			}

			/*
			 * give the extension the server options
			 */
			if (a && lws_ext_parse_options(ext, wsi,
					wsi->ws->act_ext_user[
					                wsi->ws->count_act_ext],
					opts, a, lws_ptr_diff(c, a))) {
				lwsl_err("%s: unable to parse remote def '%s'",
					 __func__, a);
				*cce = "HS: EXT: failed parsing options";
				goto bail2;
			}

			if (ext->callback(lws_get_context(wsi), ext, wsi,
					LWS_EXT_CB_OPTION_CONFIRM,
				      wsi->ws->act_ext_user[wsi->ws->count_act_ext],
				      NULL, 0)) {
				lwsl_err("%s: ext %s rejects server options %s",
					 __func__, ext->name, a);
				*cce = "HS: EXT: Rejects server options";
				goto bail2;
			}

			wsi->ws->count_act_ext++;

			ext++;
		}

		if (n == 0) {
			lwsl_warn("Unknown ext '%s'!\n", ext_name);
			*cce = "HS: EXT: unknown ext";
			goto bail2;
		}

		a = NULL;
		n = 0;
	}

check_accept:
#endif

	/*
	 * Confirm his accept token is the one we precomputed
	 */

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_ACCEPT);
	if (strcmp(p, wsi->http.ah->initial_handshake_hash_base64)) {
		lwsl_warn("lws_client_int_s_hs: accept '%s' wrong vs '%s'\n", p,
				  wsi->http.ah->initial_handshake_hash_base64);
		*cce = "HS: Accept hash wrong";
		goto bail2;
	}

	/* allocate the per-connection user memory (if any) */
	if (lws_ensure_user_space(wsi)) {
		lwsl_err("Problem allocating wsi user mem\n");
		*cce = "HS: OOM";
		goto bail2;
	}

	/*
	 * we seem to be good to go, give client last chance to check
	 * headers and OK it
	 */
	if (wsi->protocol->callback(wsi,
				    LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
				    wsi->user_space, NULL, 0)) {
		*cce = "HS: Rejected by filter cb";
		goto bail2;
	}

	/* clear his proxy connection timeout */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/* free up his parsing allocations */
	lws_header_table_detach(wsi, 0);

	lws_role_transition(wsi, LWSIFR_CLIENT, LRS_ESTABLISHED,
			    &role_ops_ws);
	lws_restart_ws_ping_pong_timer(wsi);

	wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/*
	 * create the frame buffer for this connection according to the
	 * size mentioned in the protocol definition.  If 0 there, then
	 * use a big default for compatibility
	 */
	n = (int)wsi->protocol->rx_buffer_size;
	if (!n)
		n = context->pt_serv_buf_size;
	n += LWS_PRE;
	wsi->ws->rx_ubuf = lws_malloc(n + 4 /* 0x0000ffff zlib */,
				"client frame buffer");
	if (!wsi->ws->rx_ubuf) {
		lwsl_err("Out of Mem allocating rx buffer %d\n", n);
		*cce = "HS: OOM";
		goto bail2;
	}
	wsi->ws->rx_ubuf_alloc = n;
	lwsl_info("Allocating client RX buffer %d\n", n);

#if !defined(LWS_WITH_ESP32)
	if (setsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_SNDBUF,
		       (const char *)&n, sizeof n)) {
		lwsl_warn("Failed to set SNDBUF to %d", n);
		*cce = "HS: SO_SNDBUF failed";
		goto bail3;
	}
#endif

	lwsl_debug("handshake OK for protocol %s\n", wsi->protocol->name);

	/* call him back to inform him he is up */

	if (wsi->protocol->callback(wsi, LWS_CALLBACK_CLIENT_ESTABLISHED,
				    wsi->user_space, NULL, 0)) {
		*cce = "HS: Rejected at CLIENT_ESTABLISHED";
		goto bail3;
	}

	return 0;

bail3:
	return 3;

bail2:
	return 2;
}
