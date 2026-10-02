#include <core.p4>
#include <v1model.p4>

/*
 * CrossState NF-1
 * Stateful TCP firewall
 *
 * G1 target:
 *   P4 / BMv2 behavior must match ref/model.py
 *
 * Normative semantics:
 *   - canonical bidirectional TCP key
 *   - CRC32 slot
 *   - direct-mapped register table
 *   - reject-on-collision
 *   - lazy expiry
 *   - NEW / EST / CLOSED
 */

/* =========================
 * Constants
 * ========================= */

const bit<48> T_US = 48w30000000;

/* State encoding */
const bit<8> NEW    = 8w1;
const bit<8> EST    = 8w2;
const bit<8> CLOSED = 8w3;

/* EtherTypes */
const bit<16> ETHERTYPE_SHIM = 16w0x88B5;
const bit<16> ETHERTYPE_IPV4 = 16w0x0800;


/* =========================
 * Headers
 * ========================= */

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header shim_t {
    bit<48> ts_us;
    bit<32> pkt_id;
    bit<8>  flags;
    bit<16> inner;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> hdr_checksum;
    bit<32> src;
    bit<32> dst;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct headers_t {
    ethernet_t ethernet;
    shim_t shim;
    ipv4_t ip;
    tcp_t tcp;
}


/* =========================
 * Metadata
 * ========================= */

struct metadata_t {

    /* Computed canonical packet key */
    bit<32> ipa;
    bit<16> pa;
    bit<32> ipb;
    bit<16> pb;

    /* Hash slot */
    bit<32> slot;

    /* Stored key read from the slot */
    bit<32> kipa;
    bit<16> kpa;
    bit<32> kipb;
    bit<16> kpb;

    /* Stored state */
    bit<1> valid;
    bit<1> synced;
    bit<8>  st;
    bit<48> last;
    bit<64> pk;
    bit<64> by;

    /* Transition results */
    bit<8> new_st;
    bool allow;
    bool write_state;
    bool create;
}


/* =========================
 * Registers
 * ========================= */

/*
 * Direct-mapped CSIR slot table.
 *
 * N = 2^16 slots.
 */

register<bit<1>>(65536)  r_valid;

register<bit<32>>(65536) r_ipa;
register<bit<32>>(65536) r_ipb;

register<bit<16>>(65536) r_pa;
register<bit<16>>(65536) r_pb;

register<bit<8>>(65536)  r_st;

register<bit<48>>(65536) r_last;

register<bit<64>>(65536) r_pkts;
register<bit<64>>(65536) r_bytes;

/*
 * Migration-related registers.
 * Not exercised during initial G1 testing.
 */
register<bit<1>>(65536)  r_synced;
register<bit<32>>(65536) r_log;
register<bit<64>>(1)     r_seq;


/* =========================
 * Parser
 * ========================= */

parser MyParser(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t sm
) {

    state start {
        pkt.extract(hdr.ethernet);

        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_SHIM: parse_shim;
            default: accept;
        }
    }

    state parse_shim {
        pkt.extract(hdr.shim);

        transition select(hdr.shim.inner) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ip);

        transition select(hdr.ip.proto) {
            8w6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}


/* =========================
 * Verify checksum
 * ========================= */

control MyVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply {
    }
}


/* =========================
 * Ingress
 * ========================= */

control MyIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t sm
) {

    apply {

        /*
         * Default transition outputs.
         */
        meta.allow = false;
        meta.write_state = false;
        meta.create = false;
        meta.new_st = meta.st;

        /*
         * Only process CrossState shim + IPv4 + TCP packets.
         */
        if (
            hdr.ethernet.isValid() &&
            hdr.shim.isValid() &&
            hdr.ip.isValid() &&
            hdr.tcp.isValid() &&
            hdr.ethernet.ether_type == ETHERTYPE_SHIM &&
            hdr.shim.inner == ETHERTYPE_IPV4 &&
            hdr.ip.proto == 8w6
        ) {

            /*
             * ============================================
             * 1. Canonical bidirectional key
             * ============================================
             *
             * es = src_ip || src_port
             * ed = dst_ip || dst_port
             */
            bit<48> es;
            bit<48> ed;

            es = hdr.ip.src ++ hdr.tcp.src_port;
            ed = hdr.ip.dst ++ hdr.tcp.dst_port;

            if (es <= ed) {

                meta.ipa = hdr.ip.src;
                meta.pa  = hdr.tcp.src_port;

                meta.ipb = hdr.ip.dst;
                meta.pb  = hdr.tcp.dst_port;

            }
            else {

                meta.ipa = hdr.ip.dst;
                meta.pa  = hdr.tcp.dst_port;

                meta.ipb = hdr.ip.src;
                meta.pb  = hdr.tcp.src_port;
            }


            /*
             * ============================================
             * 2. CRC32 slot
             * ============================================
             *
             * This is the representation required by the
             * CrossState specification.
             */
            hash(
                meta.slot,
                HashAlgorithm.crc32,
                32w0,
                {
                    meta.ipa,
                    meta.pa,
                    meta.ipb,
                    meta.pb,
                    hdr.ip.proto
                },
                32w65536
            );


            /*
             * ============================================
             * 3. Read slot state
             * ============================================
             *
             * IMPORTANT:
             * packet key = ipa/pa/ipb/pb
             * stored key = kipa/kpa/kipb/kpb
             */
            r_valid.read(meta.valid, meta.slot);

            r_ipa.read(meta.kipa, meta.slot);
            r_pa.read(meta.kpa, meta.slot);

            r_ipb.read(meta.kipb, meta.slot);
            r_pb.read(meta.kpb, meta.slot);

            r_st.read(meta.st, meta.slot);
            r_last.read(meta.last, meta.slot);

            r_pkts.read(meta.pk, meta.slot);
            r_bytes.read(meta.by, meta.slot);

            r_synced.read(meta.synced, meta.slot);


            /*
             * ============================================
             * 4. Decode packet flags
             * ============================================
             */
            bool inside;
            bool shadow;

            bool syn;
            bool ack;
            bool fin;
            bool rst;

            inside = (hdr.shim.flags & 8w1) != 8w0;
            shadow = (hdr.shim.flags & 8w2) != 8w0;

            syn = (hdr.tcp.flags & 9w0x002) != 9w0x000;
            ack = (hdr.tcp.flags & 9w0x010) != 9w0x000;
            fin = (hdr.tcp.flags & 9w0x001) != 9w0x000;
            rst = (hdr.tcp.flags & 9w0x004) != 9w0x000;


            /*
             * ============================================
             * 5. Key equality / collision check
             * ============================================
             */
            bool same;

            same =
                (meta.kipa == meta.ipa) &&
                (meta.kpa  == meta.pa)  &&
                (meta.kipb == meta.ipb) &&
                (meta.kpb  == meta.pb);


            /*
             * ============================================
             * 6. Lazy expiry
             * ============================================
             */
            bool live;

            live =
                (meta.valid == 1) &&
                ((hdr.shim.ts_us - meta.last) <= T_US);


            /*
             * ============================================
             * 7. Initial SYN
             * ============================================
             */
            bool init;

            init = inside && syn && !ack;


            /*
             * ============================================
             * 8. Shadow synchronization gate
             *
             * Migration is not exercised in G1, but the
             * semantics are kept aligned with the guide.
             * ============================================
             */
            if (shadow && (meta.synced == 0)) {

                /*
                 * b3 = skipped
                 */
                hdr.shim.flags =
                    hdr.shim.flags | 8w8;

            }
            else {

                /*
                 * ========================================
                 * Case 1: empty or expired
                 * ========================================
                 */
                if (!live) {

                    if (init) {

                        meta.create = true;
                        meta.allow = true;
                        meta.write_state = true;
                        meta.new_st = NEW;
                    }
                }

                /*
                 * ========================================
                 * Case 2: live hash collision
                 * ========================================
                 */
                else if (!same) {

                    /*
                     * reject-on-collision
                     */
                    meta.allow = false;
                    meta.write_state = false;
                }

                /*
                 * ========================================
                 * Case 3a: CLOSED
                 * ========================================
                 */
                else if (meta.st == CLOSED) {

                    if (init) {

                        meta.create = true;
                        meta.allow = true;
                        meta.write_state = true;
                        meta.new_st = NEW;
                    }
                }

                /*
                 * ========================================
                 * Case 3b: FIN or RST
                 * ========================================
                 */
                else if (rst || fin) {

                    meta.new_st = CLOSED;
                    meta.allow = true;
                    meta.write_state = true;
                }

                /*
                 * ========================================
                 * Case 3c: NEW
                 * ========================================
                 */
                else if (meta.st == NEW) {

                    /*
                     * Inside traffic keeps flow NEW.
                     */
                    if (inside) {

                        meta.new_st = NEW;
                        meta.allow = true;
                        meta.write_state = true;
                    }

                    /*
                     * Outside SYN+ACK establishes flow.
                     */
                    else if (syn && ack) {

                        meta.new_st = EST;
                        meta.allow = true;
                        meta.write_state = true;
                    }
                }

                /*
                 * ========================================
                 * Case 3d: EST
                 * ========================================
                 */
                else {

                    meta.new_st = EST;
                    meta.allow = true;
                    meta.write_state = true;
                }


                /*
                 * ========================================
                 * 9. State write
                 * ========================================
                 */
                if (meta.write_state) {

                    /*
                     * New flow creation.
                     */
                    if (meta.create) {

                        r_valid.write(meta.slot, 1);

                        r_ipa.write(meta.slot, meta.ipa);
                        r_pa.write(meta.slot, meta.pa);

                        r_ipb.write(meta.slot, meta.ipb);
                        r_pb.write(meta.slot, meta.pb);

                        r_st.write(meta.slot, NEW);

                        r_last.write(
                            meta.slot,
                            hdr.shim.ts_us
                        );

                        r_pkts.write(
                            meta.slot,
                            64w1
                        );

                        r_bytes.write(
                            meta.slot,
                            (bit<64>)hdr.ip.total_len
                        );
                    }

                    /*
                     * Existing flow update.
                     */
                    else {

                        r_st.write(
                            meta.slot,
                            meta.new_st
                        );

                        r_last.write(
                            meta.slot,
                            hdr.shim.ts_us
                        );

                        r_pkts.write(
                            meta.slot,
                            meta.pk + 64w1
                        );

                        r_bytes.write(
                            meta.slot,
                            meta.by +
                            (bit<64>)hdr.ip.total_len
                        );
                    }
                }
            }


            /*
             * ============================================
             * 10. Return verdict through shim
             *
             * b2 = allow
             * ============================================
             */
            if (meta.allow) {

                hdr.shim.flags =
                    hdr.shim.flags | 8w4;
            }
        }


        /*
         * ============================================
         * BMv2 hairpin
         * ============================================
         */
        sm.egress_spec = sm.ingress_port;
    }
}


/* =========================
 * Egress
 * ========================= */

control MyEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t sm
) {
    apply {
    }
}


/* =========================
 * Checksum
 * ========================= */

control MyComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply {
        /*
         * The firewall does not modify the IPv4 header,
         * so no checksum recomputation is required here.
         */
    }
}


/* =========================
 * Deparser
 * ========================= */

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.shim);
        packet.emit(hdr.ip);
        packet.emit(hdr.tcp);
    }
}


/* =========================
 * BMv2 v1model package
 * ========================= */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
