#pragma once

#include <array>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <utility>
#include "endianness.hpp"


// TODO add support for setting and modifying extension header.
namespace RtpCpp {


template <typename C>
concept ContiguousBuffer =
    std::ranges::contiguous_range<C> && std::same_as<std::ranges::range_value_t<C>, std::uint8_t>;

template <typename C>
concept ResizableContiguousBuffer =
    ContiguousBuffer<C> && requires(C& c, std::size_t n) { c.resize(n); };

struct ExtensionHeader {
    std::uint16_t id_{};
    std::uint16_t length_{};


    void reset() {
        id_ = 0;
        length_ = 0;
    }

    [[nodiscard]] std::size_t data_size_bytes() const {
        return static_cast<std::size_t>(length_) * 4;
    }
    [[nodiscard]] std::size_t size_bytes() const { return 4 + data_size_bytes(); }
};


enum class Result : std::uint8_t {
    kSuccess,
    kBufferTooSmall,
    kFixedBufferTooSmall,
    kParseBufferOverflow,
    kParseExtensionOverflow,
    kInvalidHeaderLength,
    kInvalidRtpHeader,
    kInvalidCsrcCount,
};


// TODO add modification for extension
template <ContiguousBuffer B>
class RtpPacket {
private:
    // RTP header has minimum size of 12 bytes.
    static constexpr std::size_t kFixedRTPSize = 12;
    static constexpr std::size_t kMaxCsrcIds = 15;
    static constexpr std::uint8_t kRtpVersion = 2;
    static constexpr std::size_t kMaxFixedPktSize = kFixedRTPSize + (kMaxCsrcIds * 4);

    // using ElementT = typename B::value_type;
    using CsrcList = std::array<std::uint32_t, kMaxCsrcIds>;
    using PayloadSpan = std::span<std::uint8_t>;
    using ExtensionSpan = std::span<std::uint8_t>;
    using PacketBuffer = std::span<std::uint8_t>;

    struct Version {
        static constexpr std::size_t kOffset = 0;
        static constexpr std::uint8_t kMask = 0b1100'0000U;
        static constexpr std::uint8_t kShift = 6U;
    };

    struct PaddingBit {
        static constexpr std::size_t kOffset = 0;
        static constexpr std::uint8_t kMask = 0b0010'0000U;
        static constexpr std::uint8_t kShift = 5U;
    };

    struct ExtensionBit {
        static constexpr std::size_t kOffset = 0U;
        static constexpr std::uint8_t kMask = 0b0001'0000U;
        static constexpr std::uint8_t kShift = 4U;
    };

    struct CsrcCount {
        static constexpr std::size_t kOffset = 0U;
        static constexpr std::uint8_t kMask = 0b0000'1111U;
    };

    struct MarkerBit {
        static constexpr std::size_t kOffset = 1U;
        static constexpr std::uint8_t kMask = 0b1000'0000U;
        static constexpr std::uint8_t kShift = 7U;
    };

    struct PayloadType {
        static constexpr std::size_t kOffset = 1U;
        static constexpr std::uint8_t kMask = 0b0111'1111U;
    };


    struct SequenceNumber {
        static constexpr std::size_t kOffset = 2U;
    };

    struct Timestamp {
        static constexpr std::size_t kOffset = 4U;
    };

    struct Ssrc {
        static constexpr std::size_t kOffset = 8U;
    };

public:
    RtpPacket()
        requires ResizableContiguousBuffer<B>
        : buffer_(kFixedRTPSize)
        , packet_size_(kFixedRTPSize) {}

    explicit RtpPacket(const B& buffer)
        : buffer_(buffer){};

    RtpPacket()
        requires(std::is_same_v<B, std::span<std::uint8_t>>)
    = delete;

    RtpPacket() = default;


    [[nodiscard]] Result parse(const B& buffer) {
        buffer_ = buffer;
        on_parse(buffer_.size());
        return parse_pkt();
    }

    [[nodiscard]] Result parse(B&& buffer) {
        buffer_ = std::move(buffer);
        on_parse(buffer_.size());
        return parse_pkt();
    }

    [[nodiscard]] Result parse(B&& buffer, std::size_t packet_size) {
        buffer_ = std::move(buffer);
        on_parse(packet_size);
        return parse_pkt();
    }


    [[nodiscard]] Result parse(const B& buffer, std::size_t packet_size) {
        buffer_ = buffer;
        on_parse(packet_size);
        return parse_pkt();
    }

    [[nodiscard]] Result parse(std::size_t packet_size) {
        on_parse(packet_size);
        return parse_pkt();
    }

    [[nodiscard]] Result parse() {
        reset();
        return parse_pkt();
    }

private:
    [[nodiscard]] Result parse_pkt() {
        // std::size_t buffer_size = buffer_bytes_size();
        if (packet_size_ < kFixedRTPSize) {
            return Result::kBufferTooSmall;
        }

        payload_offset_ = kFixedRTPSize;

        // Version is the first 2 bits in octet 0
        const std::uint8_t version =
            (buffer_[Version::kOffset] & Version::kMask) >> Version::kShift;


        // RFC 3550 RTP version is 2.
        if (version != kRtpVersion) {
            return Result::kInvalidRtpHeader;
        }

        // Padding bit is the 2 bit in octet 0
        const bool is_padded =
            static_cast<int>(
                ((buffer_[PaddingBit::kOffset] & PaddingBit::kMask) >> PaddingBit::kShift) != 0U) >
            0;
        if (is_padded) {
            padding_bytes_ = buffer_[packet_size_ - 1];

            // Padding amount need to be at least 1 additional octet.
            if (padding_bytes_ == 0) {
                return Result::kInvalidRtpHeader;
            }

            // Check if padding amount exceed packet size
            if (packet_size_ < padding_bytes_ + kFixedRTPSize) {
                return Result::kParseBufferOverflow;
            }
        }

        // extension bit is the 3 bit in octet 0
        extension_bit_ =
            (((buffer_[ExtensionBit::kOffset] & ExtensionBit::kMask) >> ExtensionBit::kShift) !=
             0U);


        // csrc count is 4 bits at offset 4 octet 0
        csrc_count_ = buffer_[CsrcCount::kOffset] & CsrcCount::kMask;

        payload_offset_ += static_cast<std::size_t>(csrc_list_size());
        if (payload_offset_ > packet_size_) {
            return Result::kParseBufferOverflow;
        }

        extract_csrc();

        // marker is the first bit at octet 0.
        marker_bit_ = ((buffer_[MarkerBit::kOffset] >> MarkerBit::kShift) != 0U);


        // payload type is 7 bits at offset 2 octet 1
        payload_type_ = buffer_[PayloadType::kOffset] & PayloadType::kMask;

#ifdef RFC_3551
        if (!is_valid_pt(payload_type_)) {
            return false;
        }
#endif

        //  sequrence number is 16 bits at offset 16 octet 2 and 3
        sequence_number_ =
            read_big_endian<decltype(sequence_number_)>(&buffer_[SequenceNumber::kOffset]);

        // timestamp is 32 bits at offset 32 octet: 4, 5, 6, 7,
        timestamp_ = read_big_endian<decltype(timestamp_)>(&buffer_[Timestamp::kOffset]);

        // ssrc identifier is 32 bits at offset 64 octet: 8, 9 ,10 ,11
        ssrc_ = read_big_endian<decltype(ssrc_)>(&buffer_[Ssrc::kOffset]);

        if (extension_bit_) {
            return parse_extension();
        }

        payload_size_ = payload_size_ - payload_offset_ - static_cast<std::size_t>(padding_bytes_);


        return Result::kSuccess;
    }


    [[nodiscard]] Result parse_extension() {
        // extension start after csrc. each csrc is 32 bits (4 bytes) so we skip the
        // amount of csrc_count.
        extension_offset_ = payload_offset_;

        // extension id is the first 16 bits of extension header.
        // extension_header_->id_ = (buffer_[extension_offset] << 8U) |
        // buffer_[extension_offset + 1];
        extension_header_.id_ =
            read_big_endian<decltype(extension_header_.id_)>(&buffer_[extension_offset_]);

        // extension data length is after the extension id. which is 2 bytes from
        // the offset.
        const std::size_t length_offset = extension_offset_ + 2;

        // extension_header_->length_ = ((buffer_[length_offset] << 8U) |
        // buffer_[length_offset + 1]);
        extension_header_.length_ =
            read_big_endian<decltype(extension_header_.length_)>(&buffer_[length_offset]);

        // Check if payload offset exceed the size of packet including fixed fields
        // and padding.
        const int number_of_words = extension_header_.length_ * 4;

        // extension data is after the extension length. which is 4 bytes from the
        // extension offset.
        const std::size_t data_offset = length_offset + 2;

        payload_offset_ = data_offset + number_of_words;
        if (payload_offset_ > packet_size_) {
            return Result::kParseExtensionOverflow;
        }

        // extension_header_->data_ = buffer_.subspan(data_offset, number_of_words);
        // extension_header_.data_ = std::span<std::uint8_t>(&buffer_[data_offset],
        // number_of_words);

        payload_size_ = packet_size_ - payload_offset_ - padding_bytes_;


        return Result::kSuccess;
    }
    void extract_csrc() {
        // csrc identifier is 32 bits at offset bit 96 octet: 12 with 4 bytes each.
        // the amount of identifiers is based on ccsrc_count.
        std::size_t current_offset = kFixedRTPSize;

        for (std::size_t idx = 0; idx < csrc_count_; ++idx) {
            using CsrcElementType = std::remove_cvref_t<decltype(csrc_[idx])>;
            csrc_[idx] = read_big_endian<CsrcElementType>(&buffer_[current_offset]);
            current_offset += kCsrcIdsize;
        }
    }


public:
    // Getters
    [[nodiscard]] std::uint8_t get_csrc_count() const noexcept { return csrc_count_; }

    [[nodiscard]] bool is_marked() const noexcept { return marker_bit_; }

    [[nodiscard]] bool is_extended() const noexcept { return extension_bit_; }


    [[nodiscard]] std::uint8_t get_payload_type() const noexcept { return payload_type_; }

    [[nodiscard]] std::uint8_t get_payload_size() const noexcept { return payload_size_; }

    [[nodiscard]] std::uint16_t get_sequence_number() const noexcept { return sequence_number_; }

    [[nodiscard]] std::uint32_t get_timestamp() const noexcept { return timestamp_; }

    [[nodiscard]] std::uint32_t get_ssrc() const noexcept { return ssrc_; }

    [[nodiscard]] std::uint8_t get_padding_bytes() const noexcept { return padding_bytes_; }

    [[nodiscard]] std::uint16_t get_extension_id() const noexcept { return extension_header_.id_; }
    [[nodiscard]] std::uint16_t get_extension_length() const noexcept {
        return extension_header_.length_;
    }


    // Setters
    Result set_padding_bytes(std::uint8_t padding_bytes) {
        if constexpr (ResizableContiguousBuffer<B>) {
            const std::size_t updated_packet_size = packet_size_ - padding_bytes_ + padding_bytes;
            if (updated_packet_size > buffer_.size()) {
                buffer_.resize(updated_packet_size);
            }

        } else if (padding_bytes > buffer_.size()) {
            return Result::kBufferTooSmall;
        }


        bool pad_flag = false;
        if (padding_bytes_ > 0) {
            pad_flag = true;
            packet_size_ -= padding_bytes_;
            packet_size_ += padding_bytes;
            padding_bytes_ = padding_bytes;

            buffer_[packet_size_ - 1] = padding_bytes_;
        }

        buffer_[PaddingBit::kOffset] &= static_cast<std::uint8_t>(~PaddingBit::kMask);
        buffer_[PaddingBit::kOffset] |=
            (static_cast<std::uint8_t>(pad_flag) << PaddingBit::kShift) & PaddingBit::kMask;

        return Result::kSuccess;
    }

    void set_marker(bool mark) {
        marker_bit_ = mark;
        buffer_[MarkerBit::kOffset] &= static_cast<std::uint8_t>(~MarkerBit::kMask);
        buffer_[MarkerBit::kOffset] |=
            (static_cast<std::uint8_t>(marker_bit_) << MarkerBit::kShift) & MarkerBit::kMask;
    }

    Result set_extension(std::optional<ExtensionHeader> header) {
        if (!header.has_value()) {
            toggle_ext_bit(false);
            extension_header_.reset();
            return Result::kSuccess;
        }


        const std::size_t dst = extension_offset_ + header->size_bytes();
        const std::size_t amount = payload_size_ + padding_bytes_;
        const std::size_t updated_packet_size = dst + amount;

        if (updated_packet_size > buffer_.size()) {
            if constexpr (ResizableContiguousBuffer<B>) {
                buffer_.resize(updated_packet_size);
            } else {
                return Result::kBufferTooSmall;
            }
        }

        memmove(&buffer_[dst], &buffer_[payload_offset_], amount);
        packet_size_ = dst + amount;
        payload_offset_ = dst;
        extension_header_ = *header;

        write_big_endian(&buffer_[extension_offset_], extension_header_.id_);
        write_big_endian(&buffer_[extension_offset_ + 2], extension_header_.length_);

        return Result::kSuccess;
    }


    Result set_csrc(std::uint8_t count) {
        if (count > kMaxCsrcIds) {
            return Result::kInvalidCsrcCount;
        }


        // std::size_t csrc_end = kFixedRTPSize + (kCsrcIdsize * csrc_count_);
        const std::size_t current_csrc_offset = kFixedRTPSize + (kCsrcIdsize * csrc_count_);
        const std::size_t upcoming_csrc_offset = kFixedRTPSize + (kCsrcIdsize * count);
        const std::size_t amount = packet_size_ - current_csrc_offset;

        if (upcoming_csrc_offset + amount > buffer_.size()) {
            return Result::kBufferTooSmall;
        }


        std::memmove(&buffer_[upcoming_csrc_offset], &buffer_[current_csrc_offset], amount);

        packet_size_ = packet_size_ - (static_cast<std::size_t>(csrc_count_) * 4) +
                       (static_cast<std::size_t>(count) * 4);
        csrc_count_ = count;

        buffer_[CsrcCount::kOffset] &= (~CsrcCount::kMask);
        buffer_[CsrcCount::kOffset] |= (csrc_count_ & CsrcCount::kMask);
        write_csrc();

        return Result::kSuccess;
    }

    Result set_csrc() {
        write_csrc();
        return Result::kSuccess;
    }

    void set_payload_type(std::uint8_t payload_type) {
        payload_type_ = payload_type;
        buffer_[PayloadType::kOffset] &= static_cast<std::uint8_t>(~PayloadType::kMask);
        buffer_[PayloadType::kOffset] |= payload_type_;
    }

    void set_sequence_number(std::uint16_t sequence_number) {
        sequence_number_ = sequence_number;
        write_big_endian(&buffer_[SequenceNumber::kOffset], sequence_number_);
    }

    void set_timestamp(std::uint32_t timestamp) {
        timestamp_ = timestamp;
        write_big_endian(&buffer_[Timestamp::kOffset], timestamp_);
    }

    void set_ssrc(std::uint32_t ssrc) {
        ssrc_ = ssrc;
        write_big_endian(&buffer_[Ssrc::kOffset], ssrc_);
    }


    [[nodiscard]] std::span<std::uint32_t> csrc() noexcept {
        assert(csrc_count_ < csrc_.size());
        return std::span<std::uint32_t, kMaxCsrcIds>{csrc_};
    }


    [[nodiscard]] Result set_payload_size(std::size_t size) {
        const std::size_t end = payload_offset_ + size + padding_bytes_;

        if constexpr (ResizableContiguousBuffer<B>) {
            if (end > packet_size_) {
                buffer_.resize(end);
            }

        } else if (end > this->buffer_capacity()) {
            return Result::kBufferTooSmall;
        }

        payload_size_ = size;
        packet_size_ = end;
        // write padding to end of new size
        buffer_[packet_size_ - 1] = padding_bytes_;

        return Result::kSuccess;
    }

    PayloadSpan payload() {
        assert(payload_size_ < packet_size_ && "payload_size bigger then packet_size_ size");
        assert(payload_size_ < buffer_.size() && "payload_size bigger then buffer_ size");
        return std::span<std::uint8_t>(&buffer_[payload_offset_], payload_size_);
    }

    ExtensionSpan extension_data() {
        return ExtensionSpan(&buffer_[extension_offset_ + 4], extension_header_.data_size_bytes());
    }


    [[nodiscard]] PacketBuffer packet() {
        buffer_[Version::kOffset] &= (~Version::kMask);

        // Current RTP version is 2
        static constexpr std::uint8_t kRtpVersionBits = kRtpVersion << Version::kShift;
        buffer_[Version::kOffset] |= kRtpVersionBits;
        return std::span<std::uint8_t>(buffer_.data(), packet_size_);
    }

    // ContiguousBuffer& buffer() noexcept { return buffer_; }
    B& buffer() noexcept { return buffer_; }

    void reset() noexcept {
        extension_bit_ = false;
        csrc_count_ = 0;
        marker_bit_ = false;
        payload_offset_ = 0;
        sequence_number_ = 0;
        timestamp_ = 0;
        ssrc_ = 0;
        csrc_ = {0};
        extension_header_.reset();
        padding_bytes_ = 0;
        payload_offset_ = kFixedRTPSize;
        payload_size_ = 0;
    }


private:
    void write_csrc() {
        std::size_t current_csrc_offset = kFixedRTPSize;
        for (std::size_t idx = 0; idx < csrc_count_; ++idx) {
            write_big_endian(&buffer_[current_csrc_offset], csrc_[idx]);
            current_csrc_offset += kCsrcIdsize;
        }
    }

    [[nodiscard]] std::size_t csrc_list_size() const noexcept { return csrc_count_ * kCsrcIdsize; }
    [[nodiscard]] std::size_t buffer_capacity() const {
        if constexpr (ResizableContiguousBuffer<B>) {
            return buffer_.capacity();
        }

        return buffer_.size();
    }

    void on_parse(std::size_t packet_size) noexcept {
        reset();
        packet_size_ = packet_size;
    }

    void toggle_ext_bit(bool flag) {
        extension_bit_ = flag;
        buffer_[ExtensionBit::kOffset] &= static_cast<std::uint8_t>(~ExtensionBit::kMask);
        buffer_[ExtensionBit::kOffset] |=
            (static_cast<std::uint8_t>(extension_bit_) << ExtensionBit::kShift) &
            ExtensionBit::kMask;
    }


    static constexpr std::size_t kCsrcIdsize = 4;
    static constexpr std::size_t kMaxCsrcIdsBytes = kCsrcIdsize * kMaxCsrcIds;

    B buffer_{};
    CsrcList csrc_{};

    std::size_t extension_offset_ = kFixedRTPSize;
    std::size_t payload_offset_ = kFixedRTPSize;
    std::size_t payload_size_ = 0;
    std::size_t packet_size_ = 0;

    // Rtp fields
    std::uint32_t ssrc_ = 0;
    std::uint32_t timestamp_ = 0;

    ExtensionHeader extension_header_{};

    std::uint16_t sequence_number_ = 0;
    std::uint8_t padding_bytes_ = 0;
    std::uint8_t payload_type_ = 0;
    std::uint8_t csrc_count_ = 0;
    bool extension_bit_ = false;
    bool marker_bit_ = false;
};
}; // namespace RtpCpp
