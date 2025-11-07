#include <cstddef>
#include <cstdint>
#include <ios>
#include <iostream>
#include <ostream>
#include <span>
#ifdef RFC_3551
    #include <PayloadTypes.hpp>
#endif
#include <RtpPacket.hpp>
#include <cstring>
#include <endianness.hpp>
#include <iomanip>
#include <sstream>
#include <string_view>

/*
RTP fixed header format from RFC 3550
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


namespace RtpCpp {


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
    static constexpr std::size_t kOffset = 0;
    static constexpr std::uint8_t kMask = 0b0001'0000U;
    static constexpr std::uint8_t kShift = 4U;
};

struct CsrcCount {
    static constexpr std::size_t kOffset = 0;
    static constexpr std::uint8_t kMask = 0b0000'1111U;
};

struct MarkerBit {
    static constexpr std::size_t kOffset = 1;
    static constexpr std::uint8_t kMask = 0b1000'0000U;
    static constexpr std::uint8_t kShift = 7U;
};

struct PayloadType {
    static constexpr std::size_t kOffset = 1;
    static constexpr std::uint8_t kMask = 0b0111'1111U;
};


struct SequenceNumber {
    static constexpr std::size_t kOffset = 2;
};

struct Timestamp {
    static constexpr std::size_t kOffset = 4;
};

struct Ssrc {
    static constexpr std::size_t kOffset = 8;
};

[[nodiscard]] bool RtpPacket::parse(std::span<std::uint8_t> buffer) noexcept {
    reset();
    buffer_ = buffer;
    return parse_pkt();
}

[[nodiscard]] bool RtpPacket::parse(std::uint8_t* buffer, std::size_t size) noexcept {
    reset();
    buffer_ = {buffer, size};
    return parse_pkt();
}

[[nodiscard]] bool RtpPacket::parse() noexcept {
    return parse_pkt();
}


bool RtpPacket::parse_pkt() noexcept {
    if (buffer_.size_bytes() < kFixedRTPSize) {
        return false;
    }

    payload_offset_ = kFixedRTPSize;

    // Version is the first 2 bits in octet 0
    std::uint8_t version = (buffer_[Version::kOffset] & Version::kMask) >> Version::kShift;


    // RFC 3550 RTP version is 2.
    if (version != kRtpVersion) {
        return false;
    }

    // Padding bit is the 2 bit in octet 0

    bool is_padded =
        static_cast<int>(
            ((buffer_[PaddingBit::kOffset] & PaddingBit::kMask) >> PaddingBit::kShift) != 0U) > 0;
    if (is_padded) {
        padding_bytes_ = buffer_.back();

        // Padding amount need to be at least 1 additional octet.
        if (padding_bytes_ == 0) {
            return false;
        }

        // Check if padding amount exceed packet size
        if (buffer_.size_bytes() < padding_bytes_ + kFixedRTPSize) {
            return false;
        }
    }

    // extension bit is the 3 bit in octet 0
    extension_bit_ =
        (((buffer_[ExtensionBit::kOffset] & ExtensionBit::kMask) >> ExtensionBit::kShift) != 0U);


    // csrc count is 4 bits at offset 4 octet 0
    csrc_count_ = buffer_[CsrcCount::kOffset] & CsrcCount::kMask;

    payload_offset_ += static_cast<std::size_t>(4 * csrc_count_);
    if (payload_offset_ > buffer_.size()) {
        return false;
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
    sequence_number_ = read_big_endian<decltype(sequence_number_)>(&buffer_[SequenceNumber::kOffset]);

    // timestamp is 32 bits at offset 32 octet: 4, 5, 6, 7,
    timestamp_ = read_big_endian<decltype(timestamp_)>(&buffer_[Timestamp::kOffset]);

    // ssrc identifier is 32 bits at offset 64 octet: 8, 9 ,10 ,11
    ssrc_ = read_big_endian<decltype(ssrc_)>(&buffer_[Ssrc::kOffset]);

    if (extension_bit_) {
        return parse_extension();
    }

    payload_size_ = buffer_.size() - payload_offset_ - static_cast<std::size_t>(padding_bytes_);

    return true;
}

/* RTP extension header format from RFC 3550
 0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      defined by profile       |           length              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        header extension                       |
   |                             ....                              |

*/

bool RtpPacket::parse_extension() noexcept {
    // extension start after csrc. each csrc is 32 bits (4 bytes) so we skip the
    // amount of csrc_count.
    // const auto extension_offset = kFixedRTPSize + static_cast<std::size_t>(4 * csrc_count_);
    const std::size_t extension_offset = payload_offset_;

    extension_header_ = ExtensionHeader{};

    // extension id is the first 16 bits of extension header.
    // extension_header_->id_ = (buffer_[extension_offset] << 8U) | buffer_[extension_offset + 1];
    extension_header_->id_ =
        read_big_endian<decltype(extension_header_->id_)>(&buffer_[extension_offset]);

    // extension data length is after the extension id. which is 2 bytes from
    // the offset.
    const std::size_t length_offset = extension_offset + 2;

    // extension_header_->length_ = ((buffer_[length_offset] << 8U) | buffer_[length_offset + 1]);
    extension_header_->length_ = read_big_endian<decltype(extension_header_->length_)>(&buffer_[length_offset]);

    // TODO check if this check is working properly
    // Check if payload offset exceed the size of packet including fixed fields
    // and padding.
    const int number_of_words = extension_header_->length_ * 4;

    // extension data is after the extension length. which is 4 bytes from the
    // extension offset.
    const std::size_t data_offset = length_offset + 2;

    payload_offset_ = data_offset + number_of_words;
    if (payload_offset_ > buffer_.size()) {
        return false;
    }

    extension_header_->data_ = buffer_.subspan(data_offset, number_of_words);


    return true;
}

void reset() noexcept {}

bool RtpPacket::is_padded() const noexcept {
    return padding_bytes_ != 0U;
}

bool RtpPacket::is_extended() const noexcept {
    return extension_bit_;
}

std::uint8_t RtpPacket::get_csrc_count() const noexcept {
    return csrc_count_;
}

bool RtpPacket::is_marked() const noexcept {
    return marker_bit_;
}

std::uint8_t RtpPacket::get_payload_type() const noexcept {
    return payload_type_;
}

std::uint16_t RtpPacket::get_sequence_number() const noexcept {
    return sequence_number_;
}

std::uint32_t RtpPacket::get_timestamp() const noexcept {
    return timestamp_;
}

std::uint32_t RtpPacket::get_ssrc() const noexcept {
    return ssrc_;
}

RtpPacket::CsrcList RtpPacket::get_csrc() const noexcept {
    return csrc_;
}

std::uint8_t RtpPacket::get_padding_bytes() const noexcept {
    return padding_bytes_;
}

// TODO should it be view?
std::optional<ExtensionHeader> RtpPacket::get_extension_header() const noexcept {
    return extension_header_;
}


[[nodiscard]] std::span<std::uint8_t> RtpPacket::raw() const noexcept {
    return buffer_;
}

void RtpPacket::set_padding_bytes(std::uint8_t padding_bytes) noexcept {
    padding_bytes_ = padding_bytes;
    move_to_owned_buffer();
}

void RtpPacket::set_marker(bool mark) noexcept {
    marker_bit_ = mark;
    move_to_owned_buffer();
}


void RtpPacket::set_csrc(std::span<std::uint32_t> csrc_list) noexcept {
    if (csrc_list.size() < csrc_count_) {
        return;
    }
    std::memcpy(csrc_.data(), csrc_list.data(), csrc_count_ * sizeof(std::uint32_t));
    move_to_owned_buffer();
}


void RtpPacket::set_csrc_count(std::uint8_t count) noexcept {
    // TODO either assert or return some kind of error
    if (count > kMaxCsrcIds) {
        return;
    }

    if (count < max_csrc_count_) {
        csrc_count_overlap_bytes_ = 0;

    } else {
        csrc_count_overlap_bytes_ = count - csrc_count_;
        max_csrc_count_ = count;
    }

    csrc_count_ = count;

    move_to_owned_buffer();
}

void RtpPacket::set_payload_type(std::uint8_t payload_t) noexcept {
    payload_type_ = payload_t;
    move_to_owned_buffer();
}

void RtpPacket::set_sequence_number(std::uint16_t sequence_number) noexcept {
    sequence_number_ = sequence_number;
    move_to_owned_buffer();
}

void RtpPacket::set_timestamp(std::uint32_t timestamp) noexcept {
    timestamp_ = timestamp;
    move_to_owned_buffer();
}

void RtpPacket::set_ssrc(std::uint32_t ssrc) noexcept {
    ssrc_ = ssrc;
    move_to_owned_buffer();
}
void RtpPacket::set_payload_size(std::size_t size) {
    // TODO use assert here and what if size is smaller then 1500 but wont fit payload + rtp
    if (size > owned_buff_.max_size()) {
        return;
    }

    payload_size_ = size;
    move_to_owned_buffer();
}


RtpPacket::PayloadView RtpPacket::view_payload() noexcept {
    if (payload_offset_ < buffer_.size()) {
        return buffer_.subspan(payload_offset_, payload_size_);
    }

    return {};
}

void RtpPacket::extract_csrc() noexcept {
    // csrc identifier is 32 bits at offset bit 96 octet: 12 with 4 bytes each.
    // the amount of identifiers is based on ccsrc_count.
    std::size_t current_offset = kFixedRTPSize;

    for (std::size_t idx = 0; idx < csrc_count_; ++idx) {
        using CsrcElementType = std::remove_cvref_t<decltype(csrc_[idx])>;
        csrc_[idx] = read_big_endian<CsrcElementType>(&buffer_[current_offset]);
        current_offset += 4;
    }
}

std::span<std::uint8_t> RtpPacket::serialize() {
    if (!is_owning_buffer_) {
        return buffer_;
    }
    std::size_t overlapping_bytes = csrc_count_overlap_bytes_ * 4;
    std::size_t packet_size =
        payload_offset_ + payload_size_ + padding_bytes_ + csrc_count_overlap_bytes_ * 4;

    // write marking
    owned_buff_[MarkerBit::kOffset] &= static_cast<std::uint8_t>(~MarkerBit::kMask);
    owned_buff_[MarkerBit::kOffset] |=
        (static_cast<std::uint8_t>(marker_bit_) << MarkerBit::kShift) & MarkerBit::kMask;

    // write payload type
    owned_buff_[PayloadType::kOffset] &= static_cast<std::uint8_t>(~PayloadType::kMask);
    owned_buff_[PayloadType::kOffset] |= payload_type_;


    // write csrc count
    owned_buff_[CsrcCount::kOffset] |= csrc_count_ & CsrcCount::kMask;

    // Make sure payload data is not overwritten from new data.
    if (overlapping_bytes > 0) {
        std::memmove(
            &owned_buff_[payload_offset_ + overlapping_bytes],
            &owned_buff_[payload_offset_],
            payload_size_);
        payload_offset_ += overlapping_bytes;

        csrc_count_overlap_bytes_ = 0;
    }

    // write csrc list
    std::size_t current_csrc_offset = kFixedRTPSize;
    for (std::size_t idx = 0; idx < csrc_count_; ++idx) {
        std::uint32_t csrc = csrc_[idx];
        write_big_endian(&owned_buff_[current_csrc_offset], csrc);
        current_csrc_offset += 4;
    }

    // write padding
    bool pad_flag = false;
    if (padding_bytes_ > 0) {
        pad_flag = true;
        owned_buff_[packet_size - 1] = padding_bytes_;
    }
    owned_buff_[PaddingBit::kOffset] &= static_cast<std::uint8_t>(~PaddingBit::kMask);
    owned_buff_[PaddingBit::kOffset] |=
        (static_cast<std::uint8_t>(pad_flag) << PaddingBit::kShift) & PaddingBit::kMask;

    // write sequence number
    write_big_endian(&owned_buff_[SequenceNumber::kOffset], sequence_number_);

    // write timestamp
    write_big_endian(&owned_buff_[Timestamp::kOffset], timestamp_);

    // write ssrc
    write_big_endian(&owned_buff_[Ssrc::kOffset], ssrc_);


    return std::span<std::uint8_t>{owned_buff_.data(), packet_size};
}


void RtpPacket::reset() noexcept {
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
    buffer_ = {};
}

std::string RtpPacket::to_string() noexcept {
    std::string_view payload_type;

#ifdef RFC_3551
    if (is_audio_pt(payload_type_)) {
        payload_type = audio_pt_tostring(payload_type_);
    } else if (is_video_pt(payload_type_)) {
        payload_type = video_pt_tostring(payload_type_);
    } else {
        payload_type = "Dynamic RTP";
    }

#endif

    std::ostringstream oss;
    oss << "  Version: " << static_cast<unsigned>(kRtpVersion) << "\n";
    oss << "  Padded: " << (padding_bytes_ != 0U) << "\n";
    oss << "  Extended: " << extension_bit_ << "\n";
    oss << "  CSRC Count: " << static_cast<unsigned>(csrc_count_) << "\n";
    oss << "  Marked: " << marker_bit_ << "\n";
    oss << "  Payload type: " << payload_type << " " << static_cast<unsigned>(payload_type_)
        << "\n";
    oss << "  Sequence number: " << static_cast<unsigned>(sequence_number_) << "\n";
    oss << "  Timestamp: " << static_cast<unsigned>(timestamp_) << "\n";
    oss << "  SSRC: " << std::showbase << std::hex << static_cast<unsigned>(ssrc_) << "\n";
    oss << "  CSRC: [ ";

    if (csrc_count_ > 0) {
        std::size_t last_csrc = csrc_count_;
        for (std::size_t idx = 0; idx < last_csrc; ++idx) {
            oss << static_cast<unsigned>(csrc_[idx]) << ", ";
        }
        oss << static_cast<unsigned>(csrc_[last_csrc]);

    } else {
        oss << "None";
    }
    oss << " ]\n";

    auto payload = view_payload();
    if (!payload.empty()) {
        oss << std::noshowbase << std::setw(2) << std::setfill('0');
        oss << static_cast<unsigned>(payload[0]) << " ";

        std::size_t byte_end = 7;
        std::size_t line_end = 0;

        for (std::size_t idx = 1; idx < payload.size(); ++idx) {
            oss << static_cast<unsigned>(payload[idx]);
            if (idx == byte_end) {
                line_end = idx + 8;
                oss << "  ";
            } else if (idx == line_end) {
                byte_end = idx + 8;
                oss << "\n";
            } else {
                oss << " ";
            }
        }
        oss << "\n";
    }

    if (extension_bit_ && extension_header_) {
        oss << "Extension Header ID: " << static_cast<unsigned>(extension_header_->id_) << "\n";
        oss << "Extension Header Length: " << static_cast<unsigned>(extension_header_->length_)
            << "\n";


        oss << std::noshowbase << std::setw(2) << std::setfill('0');
        auto& extension_data = extension_header_->data_;

        oss << static_cast<unsigned>(extension_data[0]) << " ";

        std::size_t byte_end = 7;
        std::size_t line_end = 0;

        for (std::size_t idx = 1; idx < extension_data.size(); ++idx) {
            oss << static_cast<unsigned>(extension_data[idx]);
            if (idx == byte_end) {
                line_end = idx + 8;
                oss << "  ";
            } else if (idx == line_end) {
                byte_end = idx + 8;
                oss << "\n";
            } else {
                oss << " ";
            }
        }
        oss << "\n";
    }

    return oss.str();
}

} // namespace RtpCpp