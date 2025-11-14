#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>


// TODO add support for setting and modifying extension header.

namespace RtpCpp {

struct ExtensionHeader {
    std::uint16_t id_;
    std::uint16_t length_;
    std::span<std::uint8_t> data_;
};


class RtpPacket {
    // RTP header has minimum size of 12 bytes.
    static constexpr std::size_t kFixedRTPSize = 12;
    static constexpr std::size_t kMaxCsrcIds = 15;
    static constexpr std::uint8_t kRtpVersion = 2;
    using CsrcList = std::array<std::uint32_t, kMaxCsrcIds>;
    using PayloadView = std::span<std::uint8_t>;

    static constexpr std::size_t kMaxFixedPktSize = kFixedRTPSize + (kMaxCsrcIds * 4);

public:
    RtpPacket() noexcept = default;
    explicit RtpPacket(std::span<std::uint8_t> buffer) noexcept
        : buffer_(buffer) {}
    RtpPacket(std::uint8_t* buffer, const std::size_t size) noexcept
        : buffer_(buffer, size) {}

    [[nodiscard]] bool parse(std::span<std::uint8_t> buffer) noexcept;
    [[nodiscard]] bool parse(std::uint8_t* buffer, std::size_t size) noexcept;
    [[nodiscard]] bool parse() noexcept;

    void reset() noexcept;

    // Getters
    [[nodiscard]] bool is_padded() const noexcept;
    [[nodiscard]] bool is_extended() const noexcept;
    [[nodiscard]] bool is_marked() const noexcept;

    [[nodiscard]] std::uint8_t get_csrc_count() const noexcept;
    [[nodiscard]] std::uint8_t get_payload_type() const noexcept;
    [[nodiscard]] std::uint16_t get_sequence_number() const noexcept;
    [[nodiscard]] std::uint32_t get_timestamp() const noexcept;
    [[nodiscard]] std::uint32_t get_ssrc() const noexcept;
    [[nodiscard]] std::uint8_t get_padding_bytes() const noexcept;

    [[nodiscard]] CsrcList get_csrc() const noexcept;

    [[nodiscard]] std::optional<ExtensionHeader> get_extension_header() const noexcept;

    [[nodiscard]] std::span<std::uint8_t> raw() const noexcept;


    // Setters

    void set_padding_bytes(std::uint8_t padding_bytes) noexcept;
    void set_extension_header(ExtensionHeader& extension_header) noexcept;
    void set_marker(bool mark) noexcept;
    void set_csrc(std::span<std::uint32_t> csrc_list) noexcept;
    void set_csrc_count(std::uint8_t count) noexcept;
    void set_payload_type(std::uint8_t payload_t) noexcept;
    void set_sequence_number(std::uint16_t sequence_number) noexcept;
    void set_timestamp(std::uint32_t timestamp) noexcept;
    void set_ssrc(std::uint32_t ssrc) noexcept;

    void set_payload_size(std::size_t size);

    // viewers

    PayloadView view_payload() noexcept;

    std::string to_string() noexcept;


    std::span<std::uint8_t> serialize();

private:
    [[nodiscard]] bool parse_pkt() noexcept;
    [[nodiscard]] bool parse_extension() noexcept;
    [[nodiscard]] std::size_t csrc_list_size() const { return csrc_count_ * kCsrcIdsize; }
    void move_to_owned_buffer() {
        if (!is_owning_buffer_) {
            std::memcpy(owned_buff_.data(), buffer_.data(), buffer_.size_bytes());
            std::size_t csrc_bytes_size = csrc_list_size();
            std::memcpy(
                &owned_buff_[owned_buffer_offset_ - csrc_bytes_size],
                buffer_.data(),
                buffer_.size_bytes());
            payload_offset_ = headroom_;

            if (extension_header_) {
                // length is in 32 bits. header length and id fields are 16 bits each.
                payload_offset_ += static_cast<std::size_t>(extension_header_->length_) * 4 + 4;
            }

            is_owning_buffer_ = true;
        }
    }
    void extract_csrc() noexcept;

    static constexpr std::size_t kCsrcIdsize = 4;
    static constexpr std::size_t kMaxCsrcIdsBytes = kCsrcIdsize * kMaxCsrcIds;


    // fixed header fields
    bool extension_bit_{};
    std::uint8_t csrc_count_{};
    bool marker_bit_ = false;
    std::uint8_t payload_type_{};
    std::uint16_t sequence_number_{};
    std::uint32_t timestamp_{};
    std::uint32_t ssrc_{};
    CsrcList csrc_{};

    std::optional<ExtensionHeader> extension_header_;

    std::uint8_t padding_bytes_ = 0;

    std::size_t payload_offset_ = kFixedRTPSize;
    std::size_t payload_size_{};

    std::span<std::uint8_t> buffer_;

    std::array<std::uint8_t, 1500> owned_buff_{};

    bool is_owning_buffer_ = false;

    // std::vector<std::uint8_t> dyn_buffer_;
    std::size_t owned_buffer_offset_ = kMaxCsrcIdsBytes;
    std::size_t headroom_ = kFixedRTPSize + kMaxCsrcIdsBytes;
};

} // namespace RtpCpp