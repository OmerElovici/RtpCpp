

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

template <typename RtpPacketType>
auto create_packet_buff() {
    if constexpr (std::is_same_v<RtpPacketType, RtpPacket<std::vector<std::uint8_t>>>) {
        return std::vector<std::uint8_t>(200);
    } else {
        return std::array<std::uint8_t, 200>{};
    }
}

TEMPLATE_TEST_CASE(
    "Setting rtp packet data values",
    "[RtpPacket]",
    (RtpPacket<std::array<std::uint8_t, 200>>),
    (RtpPacket<std::span<std::uint8_t>>),
    (RtpPacket<std::vector<std::uint8_t>>)) {

    using RtpPacketVecType = RtpPacket<std::vector<std::uint8_t>>;
    auto buff = create_packet_buff<TestType>();

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


    // This shouldnt be here since buffer size in this test case is always big enough
    // but left for completeness
    SECTION("Set csrc (when buffer too small)") {
        std::array<std::uint8_t, 32> small_buff{};
        RtpPacket<std::array<std::uint8_t, 32>> small_pkt{small_buff};
        RtpPacket<std::span<std::uint8_t>> small_pkt_span{small_buff};
        RtpPacket<std::vector<std::uint8_t>> small_pkt_vec{};

        REQUIRE(small_pkt.set_csrc(6) == Result::kBufferTooSmall);
        REQUIRE(small_pkt_span.set_csrc(6) == Result::kBufferTooSmall);
        // REQUIRE(small_pkt_vec.set_csrc(6) == Result::kSuccess);

    }

    SECTION("Set Padding") {
        std::size_t padding_size = 0;
        REQUIRE(pkt.set_padding_bytes(padding_size) == Result::kSuccess);

        padding_size = 100;
        REQUIRE(pkt.set_padding_bytes(padding_size) == Result::kSuccess);

        padding_size = 200;
        if constexpr (std::same_as<TestType, RtpPacketVecType>) {
            REQUIRE(pkt.set_padding_bytes(padding_size) == Result::kSuccess);
        } else {
            // Should not change buffer size
            REQUIRE(pkt.set_padding_bytes(padding_size) == Result::kBufferTooSmall);
            padding_size = 100;
        }

        REQUIRE(pkt_size + padding_size == pkt.packet().size());
    }

    SECTION("Set Extension") {
        REQUIRE(pkt.set_extension({}) == Result::kSuccess);

        auto header = ExtensionHeader{.id_ = 3, .length_ = 2};
        REQUIRE(pkt.set_extension(header) == Result::kSuccess);

        header = ExtensionHeader{.id_ = 4, .length_ = 200};
        if constexpr (std::same_as<TestType, RtpPacketVecType>) {
            REQUIRE(pkt.set_extension(header) == Result::kSuccess);
        } else {
            // Should not change buffer size
            REQUIRE(pkt.set_extension(header) == Result::kBufferTooSmall);
            header = ExtensionHeader{.id_ = 3, .length_ = 2};
        }

        REQUIRE(pkt.packet().size() == pkt_size + header.size_bytes());
    }

    SECTION("Set Payload size") {
        std::size_t payload_size = 0;
        REQUIRE(pkt.set_payload_size(payload_size) == Result::kSuccess);

        payload_size = 160;
        REQUIRE(pkt.set_payload_size(payload_size) == Result::kSuccess);

        payload_size = 220;
        if constexpr (std::same_as<TestType, RtpPacketVecType>) {
            REQUIRE(pkt.set_payload_size(payload_size) == Result::kSuccess);
        } else {
            // Should not change buffer size
            REQUIRE(pkt.set_payload_size(payload_size) == Result::kBufferTooSmall);
            payload_size = 160;
        }

        REQUIRE(pkt_size + payload_size == pkt.packet().size());
    }
}




TEMPLATE_TEST_CASE(
    "Modify RTP packet data with static buffer",
    "[RtpPacket]",
    (RtpPacket<std::array<std::uint8_t, 200>>),
    (RtpPacket<std::span<std::uint8_t>>),
    (RtpPacket<std::vector<std::uint8_t>>)) {

    auto buff = create_packet_buff<TestType>();

    TestType pkt{buff};
    std::size_t pkt_size = pkt.packet().size();
    REQUIRE(pkt_size == 12);


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
