#include <array>
#include <cassert>
#include <cstdint>
#include <epan/address.h>
#include <epan/column-info.h>
#include <epan/column-utils.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <wsutil/inet_cidr.h>

extern "C"
{
// symbols required by epan
const char* plugin_version{ "0.0.1" };
int plugin_want_major{ 4 };
int plugin_want_minor{ 4 };
}

namespace
{

constexpr const char* PROTO_NAME{ "HEP3" };

int g_protoHep3Id{ -1 };
int g_ettHep3{ -1 };

dissector_handle_t g_hep3Handle{ nullptr };
dissector_handle_t g_sipHandle{ nullptr };

int g_hfHepVersion{ -1 };
int g_hfHepPacketSize{ -1 };
int g_hfHepIpFamily{ -1 };
int g_hfHepIpProto{ -1 };
int g_hfHepSrcPort{ -1 };
int g_hfDstPort{ -1 };
int g_hfHepSrcIp{ -1 };
int g_hfHepDspIp{ -1 };
int g_hfHepProtocolType{ -1 };
int g_hfHepPayload{ -1 };

std::array g_hfRegisterData{
    hf_register_info{ &g_hfHepVersion,
                     { "HepP Version", "hep3.version", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL }                  },

    hf_register_info{ &g_hfHepPacketSize,
                     { "Packet Size", "hep3.size", FT_UINT16, BASE_DEC, nullptr, 0x0, nullptr, HFILL }                       },

    hf_register_info{ &g_hfHepIpFamily,
                     { "IP Family", "hep3.ip_family", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL }                   },

    hf_register_info{ &g_hfHepIpProto,
                     { "IP Protocol", "hep3.ip_proto", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL }                  },

    hf_register_info{ &g_hfHepSrcPort,
                     { "Source Port", "hep3.src_port", FT_UINT16, BASE_DEC, nullptr, 0x0, nullptr, HFILL }                   },

    hf_register_info{ &g_hfDstPort,
                     { "Destination Port", "hep3.dst_port", FT_UINT16, BASE_DEC, nullptr, 0x0, nullptr, HFILL }              },

    hf_register_info{ &g_hfHepSrcIp,        { "Source IP", "hep3.src_ip", FT_IPv4, BASE_NONE, nullptr, 0x0, nullptr, HFILL } },

    hf_register_info{ &g_hfHepDspIp,
                     { "Destination IP", "hep3.dst_ip", FT_IPv4, BASE_NONE, nullptr, 0x0, nullptr, HFILL }                   },

    hf_register_info{ &g_hfHepProtocolType,
                     { "Hep Protocol", "hep3.proto", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL }                    },

    hf_register_info{ &g_hfHepPayload,
                     { "Payload", "hep3.payload", FT_BYTES, BASE_NONE, nullptr, 0x0, nullptr, HFILL }                        },
};

std::array g_ettData{ &g_ettHep3 };

[[maybe_unused]] constexpr uint8_t ONE_BYTE_SIZE{ 1 };
constexpr uint8_t TWO_BYTE_SIZE{ 2 };
constexpr uint8_t FOUR_BYTE_SIZE{ 4 };

constexpr const char* IpFamilyName(uint8_t val) noexcept
{
    switch (val)
    {
        case AF_UNSPEC:
            return "Unspecified";
        case AF_LOCAL:
            return "Local";
        case AF_INET:
            return "IPv4";
        case AF_INET6:
            return "IPv6";
        case AF_BLUETOOTH:
            return "Bluetooth";
        default:
            return "Uknown IP Family";
    }
}

constexpr const char* IpProtoName(uint8_t val) noexcept
{
    switch (val)
    {
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_UDPLITE:
            return "UDP-Lite";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_SCTP:
            return "SCTP";
        default:
            return "Unknown IP Protocol";
    }
}

constexpr const char* HepProtoName(uint8_t val) noexcept
{
    switch (val)
    {
        case 0x00:
            return "RESERVED";
        case 0x01:
            return "SIP";
        case 0x02:
            return "XMPP";
        case 0x03:
            return "SDP";
        case 0x04:
            return "RTP";
        case 0x05:
            return "RTCP JSON";
        case 0x06:
            return "MGCP";
        case 0x07:
            return "MEGACO (H.248)";
        case 0x08:
            return "M2UA (SS7/SIGTRAN)";
        case 0x09:
            return "M3UA (SS7/SIGTRAN)";
        case 0x0a:
            return "IAX";
        case 0x0b:
            return "H3222";
        case 0x0c:
            return "H321";
        case 0x0d:
            return "M2PA";
        case 0x22:
            return "MOS full report [JSON]";
        case 0x23:
            return "MOS short report [JSON]";
        case 0x32:
            return "SIP JSON";
        case 0x33:
        case 0x34:
            return "RESERVED";
        case 0x35:
            return "DNS JSON";
        case 0x36:
            return "M3UA JSON (ISUP)";
        case 0x37:
            return "RTSP (JSON)";
        case 0x38:
            return "DIAMETER (JSON)";
        case 0x39:
            return "GSM MAP (JSON)";
        case 0x3a:
            return "RTCP PION";
        case 0x3b:
            return "RESERVED";
        case 0x3c:
            return "CDR";
        case 0x3d:
            return "Verto (JSON event/signaling protocol)";
        default:
            return "Unknown";
    }
}

void DissectHep3(tvbuff_t& buffer, packet_info& pinfo, proto_tree& hepTree, proto_tree& parentTree)
{
    int offset{ 0 };

    // version
    if (tvb_reported_length(&buffer) < FOUR_BYTE_SIZE)
    {
        // not enough for header
        return;
    }

    auto version{ tvb_get_uint32(&buffer, offset, ENC_BIG_ENDIAN) };
    if (version != 0x48455033)
    {
        // aka is not 'HEP3'
        return;
    }

    proto_tree_add_item(&hepTree, g_hfHepVersion, &buffer, offset, FOUR_BYTE_SIZE, ENC_BIG_ENDIAN);
    offset += FOUR_BYTE_SIZE;

    // packet len
    proto_tree_add_item(&hepTree, g_hfHepPacketSize, &buffer, offset, TWO_BYTE_SIZE, ENC_BIG_ENDIAN);
    offset += TWO_BYTE_SIZE;

    uint8_t currProtoType{ 0 };

    static constexpr auto CHUNK_HEADER_LEN{ TWO_BYTE_SIZE * 3 };
    while (true)
    {
        auto bytesLeft = tvb_reported_length_remaining(&buffer, offset);
        if (bytesLeft < CHUNK_HEADER_LEN)
        {
            // not enough for chunk header
            break;
        }

        [[maybe_unused]] auto chuckVenderId{ tvb_get_uint16(&buffer, offset, ENC_BIG_ENDIAN) };
        offset += TWO_BYTE_SIZE;

        auto chuckType{ tvb_get_uint16(&buffer, offset, ENC_BIG_ENDIAN) };
        offset += TWO_BYTE_SIZE;

        auto chuckLen{ tvb_get_uint16(&buffer, offset, ENC_BIG_ENDIAN) };
        offset += TWO_BYTE_SIZE;
        auto payloadLen{ chuckLen - CHUNK_HEADER_LEN };

        if (bytesLeft < payloadLen)
        {
            // not enough for payload
            break;
        }

        switch (chuckType)
        {
            case 0x01:
            {
                proto_tree_add_string(
                    &hepTree, g_hfHepIpFamily, &buffer, offset, payloadLen, IpFamilyName(tvb_get_uint8(&buffer, offset))
                );
                break;
            }
            case 0x02:
            {
                proto_tree_add_string(
                    &hepTree, g_hfHepIpProto, &buffer, offset, payloadLen, IpProtoName(tvb_get_uint8(&buffer, offset))
                );
                break;
            }
            case 0x03:
            {
                auto ip = tvb_get_ipv4(&buffer, offset);
                ipv4_addr_and_mask val{ .addr = ntohl(ip), .nmask = 0 };
                set_address_ipv4(&pinfo.src, &val);
                proto_tree_add_ipv4(&hepTree, g_hfHepSrcIp, &buffer, offset, payloadLen, ip);
                break;
            }
            case 0x04:
            {
                auto ip = tvb_get_ipv4(&buffer, offset);
                ipv4_addr_and_mask val{ .addr = ntohl(ip), .nmask = 0 };
                set_address_ipv4(&pinfo.dst, &val);
                proto_tree_add_ipv4(&hepTree, g_hfHepDspIp, &buffer, offset, payloadLen, ip);
                break;
            }
            case 7:
            {
                pinfo.srcport = tvb_get_uint16(&buffer, offset, ENC_BIG_ENDIAN);
                proto_tree_add_item(&hepTree, g_hfHepSrcPort, &buffer, offset, payloadLen, ENC_BIG_ENDIAN);
                break;
            }
            case 8:
            {
                pinfo.destport = tvb_get_uint16(&buffer, offset, ENC_BIG_ENDIAN);
                proto_tree_add_item(&hepTree, g_hfDstPort, &buffer, offset, payloadLen, ENC_BIG_ENDIAN);
                break;
            }
            case 0x0b:
            {
                currProtoType = tvb_get_uint8(&buffer, offset);
                proto_tree_add_string(
                    &hepTree,
                    g_hfHepProtocolType,
                    &buffer,
                    offset,
                    payloadLen,
                    HepProtoName(tvb_get_uint8(&buffer, offset))
                );
                break;
            }
            case 0x0f:
            {
                auto capture_payload = tvb_new_subset_length(&buffer, offset, payloadLen);
                proto_tree_add_item(&hepTree, g_hfHepPayload, &buffer, offset, payloadLen, ENC_NA);

                auto hepProto{ HepProtoName(currProtoType) };
                std::string protocolStr{ std::string{ PROTO_NAME } + '/' + hepProto };
                col_set_str(pinfo.cinfo, COL_PROTOCOL, protocolStr.c_str());

                if (hepProto == std::string_view{ "SIP" })
                {
                    call_dissector(g_sipHandle, capture_payload, &pinfo, &parentTree);
                }

                currProtoType = 0;
                break;
            }
            default:
                break;
        }

        offset += payloadLen;
    }
}

void RegisterHep3Handoff()
{
    static std::once_flag s_onceFlag{};
    std::call_once(
        s_onceFlag,
        []
        {
            g_hep3Handle = create_dissector_handle_with_name_and_description(
                +[](tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, [[maybe_unused]] void* args) -> int
                {
                    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HEP3");

                    proto_item* rootTree = proto_tree_add_item(tree, g_protoHep3Id, tvb, 0, -1, ENC_NA);
                    proto_tree* hepRoot = proto_item_add_subtree(rootTree, g_ettHep3);

                    DissectHep3(*tvb, *pinfo, *hepRoot, *rootTree);

                    return static_cast<int>(tvb_reported_length(tvb));
                },
                g_protoHep3Id,
                "Hep3",
                "Hep3"
            );

            g_sipHandle = find_dissector("sip");

            assert(g_hep3Handle != nullptr);
            assert(g_sipHandle != nullptr);

            dissector_add_uint("udp.port", 9060, g_hep3Handle);
            dissector_add_uint("udp.port", 9063, g_hep3Handle);
            dissector_add_uint("tcp.port", 9060, g_hep3Handle);
            dissector_add_uint("tcp.port", 9062, g_hep3Handle);
        }
    );
}

void RegisterHep3ProtoInfo()
{
    static std::once_flag s_onceFlag{};
    std::call_once(
        s_onceFlag,
        []
        {
            g_protoHep3Id = proto_register_protocol(PROTO_NAME, PROTO_NAME, "hep3");
            proto_register_field_array(g_protoHep3Id, g_hfRegisterData.data(), g_hfRegisterData.size());
            proto_register_subtree_array(g_ettData.data(), g_ettData.size());
        }
    );
}

} // namespace

extern "C" void plugin_register(void)
{
    static const proto_plugin s_hep3Plugin{ .register_protoinfo = &RegisterHep3ProtoInfo,
                                            .register_handoff = &RegisterHep3Handoff };
    static std::once_flag s_onceFlag{};
    std::call_once(s_onceFlag, [] { proto_register_plugin(&s_hep3Plugin); });
}
