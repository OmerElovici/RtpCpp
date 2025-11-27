
#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <span>
#include <vector>
#include "../include//RtpPacket.hpp"
#include "catch2/catch_message.hpp"
#include "packet_samples.hpp"

using namespace RtpCpp;
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while, readability-function-cognitive-complexity)

TEST_CASE("Parse RTP packets from buffer", "[RtpPacket]") {
    SECTION("Valid regular packet") {
        auto check_fields = [](auto&& rtp_packet, const char* file, int line) {
            INFO("Failure located at: " << file << ":" << line);

            REQUIRE(rtp_packet.packet().size() == 172);
            REQUIRE_FALSE(rtp_packet.get_padding_bytes() > 0);
            REQUIRE_FALSE(rtp_packet.is_extended());
            REQUIRE_FALSE(rtp_packet.is_marked());
            REQUIRE(rtp_packet.get_csrc_count() == 0);
            REQUIRE(rtp_packet.get_payload_type() == 8);
            REQUIRE(rtp_packet.get_sequence_number() == 1);
            REQUIRE(rtp_packet.get_timestamp() == 160);
            REQUIRE(rtp_packet.get_ssrc() == 0x12345678);
        };

        // Static buffer
        RtpPacket<std::array<std::uint8_t, RtpSamples::kG711PcmaSize>> arr_pkt;
        REQUIRE(arr_pkt.parse(RtpSamples::g711_pcma) == Result::kSuccess);
        check_fields(arr_pkt, __FILE__, __LINE__);

        // Dynamic buffer
        RtpPacket<std::vector<std::uint8_t>> vec_pkt;
        std::vector<std::uint8_t> vec_buffer(
            RtpSamples::g711_pcma.begin(),
            RtpSamples::g711_pcma.end());
        REQUIRE(vec_pkt.parse(std::move(vec_buffer)) == Result::kSuccess);
        check_fields(vec_pkt, __FILE__, __LINE__);

        // Span buffer
        RtpPacket<std::span<std::uint8_t>> span_pkt;
        auto arr_buffer = RtpSamples::g711_pcma;
        REQUIRE(span_pkt.parse({arr_buffer}) == Result::kSuccess);
        check_fields(span_pkt, __FILE__, __LINE__);
    }

    SECTION("Valid packet with all fields enabled") {
        auto check_fields = [](auto&& rtp_packet, const char* file, int line) {
            constexpr std::array<std::uint32_t, 15> kSampleCsrcList = {0x00000011, 0x00000022};
            constexpr auto kSampleExtensionData =
                std::span<const std::uint8_t>(RtpSamples::all_enabled).subspan(24, 4);
            constexpr auto kSamplePayload =
                std::span<const std::uint8_t>(RtpSamples::all_enabled).subspan(28, 3);

            INFO("Failure located at: " << file << ":" << line);

            REQUIRE(rtp_packet.packet().size() == 35);
            REQUIRE(rtp_packet.get_padding_bytes() == 4);
            REQUIRE(rtp_packet.is_extended());
            REQUIRE(rtp_packet.is_marked());

            REQUIRE(rtp_packet.get_csrc_count() == 2);
            REQUIRE(std::ranges::equal(rtp_packet.csrc(), kSampleCsrcList));

            REQUIRE(rtp_packet.get_extension_id() == 0xBEDE);

            REQUIRE(rtp_packet.get_extension_length() == 0x0001);

            auto parsed_extension_data = rtp_packet.extension_data();
            REQUIRE(std::ranges::equal(parsed_extension_data, kSampleExtensionData));

            REQUIRE(rtp_packet.get_payload_type() == 127);
            REQUIRE(rtp_packet.get_sequence_number() == 6);
            REQUIRE(rtp_packet.get_timestamp() == 512);
            REQUIRE(rtp_packet.get_ssrc() == 0x55667788);
            auto parsed_payload = rtp_packet.payload();
            REQUIRE(std::ranges::equal(parsed_payload, kSamplePayload));
        };

        RtpPacket<std::array<std::uint8_t, RtpSamples::kAllEnabledSize>> arr_pkt;
        REQUIRE(arr_pkt.parse(RtpSamples::all_enabled) == Result::kSuccess);
        check_fields(arr_pkt, __FILE__, __LINE__);

        // Dynamic buffer
        RtpPacket<std::vector<std::uint8_t>> vec_pkt;
        std::vector<std::uint8_t> vec_buffer(
            RtpSamples::all_enabled.begin(),
            RtpSamples::all_enabled.end());
        REQUIRE(vec_pkt.parse(std::move(vec_buffer)) == Result::kSuccess);
        check_fields(vec_pkt, __FILE__, __LINE__);

        // Span buffer
        RtpPacket<std::span<std::uint8_t>> span_pkt;
        auto arr_buffer = RtpSamples::all_enabled;
        REQUIRE(span_pkt.parse({arr_buffer}) == Result::kSuccess);
        check_fields(span_pkt, __FILE__, __LINE__);
    }
}

TEST_CASE("Parse invalid RTP packets", "[RtpPacket]") {
    RtpPacket<std::span<const std::uint8_t>> pkt;

    SECTION("Invalid version") {
        auto invalid_ver_pkt = RtpSamples::invalid_version;
        REQUIRE(pkt.parse(RtpSamples::invalid_version) == Result::kInvalidRtpHeader);
    }

    SECTION("Invalid padding size (size = 0)") {
        REQUIRE(pkt.parse(RtpSamples::invalid_padding) == Result::kInvalidRtpHeader);
    }

    SECTION("Padding size overflow packet size") {
        REQUIRE(pkt.parse(RtpSamples::padding_overflow) == Result::kParseBufferOverflow);
    }

    SECTION("Csrc identifiers overflow packet size") {
        REQUIRE(pkt.parse(RtpSamples::invalid_csrc) == Result::kParseBufferOverflow);
    }

    SECTION("Extension data overflow packet size") {
        REQUIRE_FALSE(pkt.parse(RtpSamples::invalid_extension) == Result::kParseBufferOverflow);
    }
}

// NOLINTEND(cppcoreguidelines-avoid-do-while, readability-function-cognitive-complexity)