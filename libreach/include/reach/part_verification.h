// SPDX-License-Identifier: MIT
#pragma once
namespace reach {
enum class PartVerification { Unavailable, Corrupt, Verified };
// Main-thread authoritative hash callback input. An unchecked digest is not
// evidence; disagreement between checked MD4/AICH results is not success.
inline PartVerification ClassifyPartVerification(bool md4Checked,bool md4Error,
    bool aichChecked,bool aichError) noexcept {
    if((md4Checked && md4Error) || (aichChecked && aichError)) return PartVerification::Corrupt;
    if(md4Checked || aichChecked) return PartVerification::Verified;
    return PartVerification::Unavailable;
}
}
