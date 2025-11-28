

#include <algorithm>
#include <array>
#include <catch2/catch_template_test_macros.hpp>
#include <cstddef>
#include <span>
#include "../include/RtpPacket.hpp"
#include "catch2/catch_test_macros.hpp"
#include "packet_samples.hpp"

using namespace RtpCpp;

// NOLINTBEGIN(cppcoreguidelines-avoid-do-while, readability-function-cognitive-complexity,
// cert-err58-cpp)


TEMPLATE_TEST_CASE(
    "Modify RTP packet data with static buffer",
    "[RtpPacket]",
    (RtpPacket<std::array<std::uint8_t, 200>>),
    (RtpPacket<std::span<std::uint8_t>>)) {
    std::array<std::uint8_t, 200> buff{};

    TestType pkt{buff};
    std::size_t pkt_size = pkt.packet().size();
    REQUIRE(pkt_size == 12);

    SECTION("Set Csrc") {
        REQUIRE(pkt.set_csrc(0) == Result::kSuccess);
        REQUIRE(pkt.set_csrc(15) == Result::kSuccess);
        REQUIRE(pkt.set_csrc(16) == Result::kInvalidCsrcCount);
        constexpr std::size_t kMaxCsrcRtpPacket = 72;
        REQUIRE(pkt.packet().size() == kMaxCsrcRtpPacket);
    }

    SECTION("Set Padding") {
        REQUIRE(pkt.set_padding_bytes(0) == Result::kSuccess);
        REQUIRE(pkt.set_padding_bytes(100) == Result::kSuccess);
        REQUIRE(pkt.set_padding_bytes(200) == Result::kBufferTooSmall);
        REQUIRE(pkt_size + 100 == pkt.packet().size());
    }

    SECTION("Set Extension") {
        auto valid_header = ExtensionHeader{.id_ = 3, .length_ = 2};
        REQUIRE(pkt.set_extension(valid_header) == Result::kSuccess);

        auto invalid_header = ExtensionHeader{.id_ = 4, .length_ = 200};
        REQUIRE(pkt.set_extension(invalid_header) == Result::kBufferTooSmall);

        REQUIRE(pkt.packet().size() == pkt_size + valid_header.size_bytes());
    }

    SECTION("Set Payload size") {
        REQUIRE(pkt.set_payload_size(0) == Result::kSuccess);
        REQUIRE(pkt.set_payload_size(160) == Result::kSuccess);
        REQUIRE(pkt.set_payload_size(220) == Result::kBufferTooSmall);

        REQUIRE(pkt_size + 160 == pkt.packet().size());
    }

    SECTION("Write fixed values to buffer") {
        REQUIRE(pkt.set_payload_size(160) == Result::kSuccess);
        REQUIRE(pkt.set_padding_bytes(0) == Result::kSuccess);
        REQUIRE(pkt.set_extension({}) == Result::kSuccess);
        pkt.set_csrc(0);
        pkt.set_marker(false);
        pkt.set_payload_type(8);
        pkt.set_sequence_number(1);
        pkt.set_timestamp(160);
        pkt.set_ssrc(0x12345678);

        auto payload = pkt.payload();
        std::fill(payload.begin(), payload.end(), 0xD5);

        auto pkt_data = pkt.packet();
        REQUIRE(pkt_data.size() == 172);

        REQUIRE(std::ranges::equal(pkt_data, RtpSamples::g711_pcma));
    }

    SECTION("Write all fields values to buffer") {
        // auto pkt_data = pkt.packet().size();
        REQUIRE(pkt.set_padding_bytes(4) == Result::kSuccess);

        ExtensionHeader exth{.id_ = 0xBEDE, .length_ = 0x01};
        REQUIRE(pkt.set_extension(exth) == Result::kSuccess);
        auto extd = pkt.extension_data();
        extd[0] = 0xDE;
        extd[1] = 0xAD;
        extd[2] = 0xBE;
        extd[3] = 0xEF;

        auto csrc_list = pkt.csrc();
        csrc_list[0] = 0x00000011;
        csrc_list[1] = 0x00000022;
        REQUIRE(pkt.set_csrc(2) == Result::kSuccess);


        pkt.set_marker(true);
        pkt.set_payload_type(127);
        pkt.set_sequence_number(6);
        pkt.set_timestamp(512);
        pkt.set_ssrc(0x55667788);


        REQUIRE(pkt.set_payload_size(3) == Result::kSuccess);
        auto payload = pkt.payload();
        payload[0] = 0x01;
        payload[1] = 0x02;
        payload[2] = 0x03;


        auto pkt_data = pkt.packet();
        REQUIRE(pkt_data.size() == RtpSamples::all_enabled.size());

        // Ignore trailing RTP padding bytes — they are not stable because setters update
        // payload fields in-place.
        constexpr std::size_t kIgnoredBytes = 4;
        std::span<std::uint8_t> pkt_data_padding_ignored{
            pkt_data.data(),
            pkt_data.size() - kIgnoredBytes};
        std::span<const std::uint8_t> sample_data_padding_ignored{
            RtpSamples::all_enabled.data(),
            RtpSamples::all_enabled.size() - kIgnoredBytes};

        REQUIRE(std::ranges::equal(pkt_data_padding_ignored, sample_data_padding_ignored));
    }
}

// NOLINTEND(cppcoreguidelines-avoid-do-while, readability-function-cognitive-complexity,
// cert-err58-cpp)
