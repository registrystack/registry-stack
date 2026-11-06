// SPDX-License-Identifier: Apache-2.0
//! ASN.1 types this module encodes or reads that no crate in the lockfile
//! provides: the RFC 3161 time-stamp protocol, the ESS signing-certificate
//! attributes of RFC 2634 and RFC 5035, and the ECDSA-Sig-Value of RFC 5480.

use cms::content_info::ContentInfo;
use der::asn1::{BitString, Int, ObjectIdentifier, OctetString, Uint};
use der::{
    DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Sequence, Tag, Writer,
};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::ext::Extensions;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

/// Object identifiers, spelled out so each can be checked against its RFC.
pub(super) mod oid {
    use der::asn1::ObjectIdentifier;

    /// id-data, RFC 5652 section 4.
    pub(crate) const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    /// id-signedData, RFC 5652 section 5.1.
    pub(crate) const SIGNED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    /// id-contentType, RFC 5652 section 11.1.
    pub(crate) const CONTENT_TYPE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    /// id-messageDigest, RFC 5652 section 11.2.
    pub(crate) const MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    /// id-signingTime, RFC 5652 section 11.3. PAdES baseline signatures must
    /// not carry it; it is named here only so tests can prove its absence.
    #[cfg(test)]
    pub(crate) const SIGNING_TIME: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
    /// id-aa-signingCertificate, RFC 2634 section 5.4.
    pub(crate) const SIGNING_CERTIFICATE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
    /// id-aa-signingCertificateV2, RFC 5035 section 3.
    pub(crate) const SIGNING_CERTIFICATE_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
    /// id-aa-signatureTimeStampToken, RFC 3161 appendix A.
    pub(crate) const SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
    /// id-ct-TSTInfo, RFC 3161 section 2.4.2.
    pub(crate) const TST_INFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

    /// id-sha256, RFC 5754 section 2.
    pub(crate) const SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    /// id-sha384, RFC 5754 section 2.
    pub(crate) const SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    /// id-sha512, RFC 5754 section 2.
    pub(crate) const SHA512: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

    /// rsaEncryption, RFC 3370 section 3.2 and RFC 8017 appendix C.
    pub(crate) const RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    /// sha256WithRSAEncryption, RFC 4055 section 5.
    pub(crate) const SHA256_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    /// sha384WithRSAEncryption, RFC 4055 section 5.
    pub(crate) const SHA384_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    /// sha512WithRSAEncryption, RFC 4055 section 5.
    pub(crate) const SHA512_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    /// ecdsa-with-SHA256, RFC 5758 section 3.2.
    pub(crate) const ECDSA_WITH_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    /// ecdsa-with-SHA384, RFC 5758 section 3.2.
    pub(crate) const ECDSA_WITH_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    /// ecdsa-with-SHA512, RFC 5758 section 3.2.
    pub(crate) const ECDSA_WITH_SHA512: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

    /// id-ecPublicKey, RFC 5480 section 2.1.1.
    pub(crate) const EC_PUBLIC_KEY: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    /// secp256r1 (P-256), RFC 5480 section 2.1.1.1.
    pub(crate) const SECP256R1: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    /// secp384r1 (P-384), RFC 5480 section 2.1.1.1.
    pub(crate) const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    /// secp521r1 (P-521), RFC 5480 section 2.1.1.1.
    pub(crate) const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

    /// id-ce-keyUsage, RFC 5280 section 4.2.1.3.
    pub(crate) const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    /// id-ce-extKeyUsage, RFC 5280 section 4.2.1.12.
    pub(crate) const EXTENDED_KEY_USAGE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.37");
    /// id-ce-subjectKeyIdentifier, RFC 5280 section 4.2.1.2.
    pub(crate) const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.14");
    /// id-kp-timeStamping, RFC 5280 section 4.2.1.12.
    pub(crate) const KP_TIME_STAMPING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
    /// anyExtendedKeyUsage, RFC 5280 section 4.2.1.12.
    pub(crate) const ANY_EXTENDED_KEY_USAGE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.37.0");
    /// id-kp-emailProtection, RFC 5280 section 4.2.1.12.
    pub(crate) const KP_EMAIL_PROTECTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
    /// id-kp-documentSigning, RFC 9336.
    pub(crate) const KP_DOCUMENT_SIGNING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.36");
    /// Microsoft's document signing purpose.
    pub(crate) const MICROSOFT_DOCUMENT_SIGNING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.12");
    /// Adobe Authentic Documents Trust.
    pub(crate) const ADOBE_AUTHENTIC_DOCUMENTS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113583.1.1.5");

    /// id-at-organizationName, RFC 5280 appendix A.1.
    pub(crate) const ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
    /// id-at-commonName, RFC 5280 appendix A.1.
    pub(crate) const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
}

/// `ECDSA-Sig-Value`, RFC 5480 section 2.2 (and RFC 3279 section 2.2.3).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct EcdsaSigValue {
    pub(super) r: Uint,
    pub(super) s: Uint,
}

/// `SigningCertificateV2`, RFC 5035 section 3.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct SigningCertificateV2 {
    pub(super) certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    pub(super) policies: Option<Vec<PolicyInformation>>,
}

/// `ESSCertIDv2`, RFC 5035 section 4. `hashAlgorithm` defaults to SHA-256,
/// so DER omits it for SHA-256 and carries it for any other hash.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct EssCertIdV2 {
    #[asn1(optional = "true")]
    pub(super) hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub(super) cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub(super) issuer_serial: Option<IssuerSerial>,
}

/// `SigningCertificate`, RFC 2634 section 5.4: the attribute a timestamp
/// authority may carry instead of [`SigningCertificateV2`] (RFC 5816).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct SigningCertificate {
    pub(super) certs: Vec<EssCertId>,
    #[asn1(optional = "true")]
    pub(super) policies: Option<Vec<PolicyInformation>>,
}

/// `ESSCertID`, RFC 2634 section 5.4.1: `certHash` is SHA-1 over the
/// certificate's DER encoding.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct EssCertId {
    pub(super) cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub(super) issuer_serial: Option<IssuerSerial>,
}

/// `IssuerSerial`, RFC 5035 section 4.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct IssuerSerial {
    pub(super) issuer: GeneralNames,
    pub(super) serial_number: SerialNumber,
}

/// `MessageImprint`, RFC 3161 section 2.4.1.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct MessageImprint {
    pub(super) hash_algorithm: AlgorithmIdentifierOwned,
    pub(super) hashed_message: OctetString,
}

/// `TimeStampReq`, RFC 3161 section 2.4.1. `certReq` defaults to FALSE; this
/// module always asks for the certificate, so it is always encoded.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct TimeStampReq {
    pub(super) version: u8,
    pub(super) message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub(super) req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub(super) nonce: Option<Uint>,
    #[asn1(optional = "true")]
    pub(super) cert_req: Option<bool>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub(super) extensions: Option<Extensions>,
}

/// `PKIStatusInfo`, RFC 3161 section 2.4.2.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct PkiStatusInfo {
    pub(super) status: u32,
    #[asn1(optional = "true")]
    pub(super) status_string: Option<Vec<String>>,
    #[asn1(optional = "true")]
    pub(super) fail_info: Option<BitString>,
}

/// `TimeStampResp`, RFC 3161 section 2.4.2.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct TimeStampResp {
    pub(super) status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub(super) time_stamp_token: Option<ContentInfo>,
}

/// `TSTInfo`, RFC 3161 section 2.4.2. The serial number and nonce are read
/// as signed integers so a token is judged on its values, not refused for
/// an encoding the module did not choose.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct TstInfo {
    pub(super) version: u8,
    pub(super) policy: TsaPolicyId,
    pub(super) message_imprint: MessageImprint,
    pub(super) serial_number: Int,
    pub(super) gen_time: TspGeneralizedTime,
    #[asn1(optional = "true")]
    pub(super) accuracy: Option<Accuracy>,
    #[asn1(optional = "true")]
    pub(super) ordering: Option<bool>,
    #[asn1(optional = "true")]
    pub(super) nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(super) tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(super) extensions: Option<Extensions>,
}

/// `TSAPolicyId`, RFC 3161 section 2.4.2: an OBJECT IDENTIFIER kept as its
/// content octets. X.660 allows arcs of any size, and a UUID-form policy
/// under 2.25 has a 128-bit arc, while `ObjectIdentifier` holds arcs below
/// 2^32 only. The policy is carried, not interpreted, so its arcs are checked
/// for well-formed base-128 encoding and not parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TsaPolicyId(Vec<u8>);

impl TsaPolicyId {
    #[cfg(test)]
    pub(super) fn from_content(content: Vec<u8>) -> Self {
        Self(content)
    }

    /// X.690 8.19.2: at least one subidentifier, each in the fewest octets
    /// (no leading 0x80) and ending with an octet whose top bit is clear.
    fn is_well_formed(content: &[u8]) -> bool {
        content.last().is_some_and(|last| last & 0x80 == 0)
            && content
                .iter()
                .enumerate()
                .all(|(at, &octet)| octet != 0x80 || (at > 0 && content[at - 1] & 0x80 != 0))
    }
}

impl From<ObjectIdentifier> for TsaPolicyId {
    fn from(oid: ObjectIdentifier) -> Self {
        Self(oid.as_bytes().to_vec())
    }
}

impl FixedTag for TsaPolicyId {
    const TAG: Tag = Tag::ObjectIdentifier;
}

impl<'a> DecodeValue<'a> for TsaPolicyId {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let content = reader.read_vec(header.length)?;
        if !Self::is_well_formed(&content) {
            return Err(ErrorKind::Value {
                tag: Tag::ObjectIdentifier,
            }
            .into());
        }
        Ok(Self(content))
    }
}

impl EncodeValue for TsaPolicyId {
    fn value_len(&self) -> der::Result<Length> {
        Length::try_from(self.0.len())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(&self.0)
    }
}

/// `Accuracy`, RFC 3161 section 2.4.2.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(super) struct Accuracy {
    #[asn1(optional = "true")]
    pub(super) seconds: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub(super) millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(super) micros: Option<u16>,
}

/// The `genTime` of a TSTInfo.
///
/// RFC 3161 section 2.4.2 allows fractional seconds (`YYYYMMDDhhmmss[.s...]Z`),
/// which the X.509 profile of `GeneralizedTime` the `der` crate implements
/// refuses, so a timestamp authority's token is read with this type instead.
/// Fractions keep up to nanosecond precision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TspGeneralizedTime(OffsetDateTime);

/// `YYYYMMDDhhmmss` plus `Z`.
const SECONDS_FORM_LEN: usize = 15;
const MAX_FRACTION_DIGITS: usize = 9;

impl TspGeneralizedTime {
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn new(value: OffsetDateTime) -> Self {
        Self(value.to_offset(time::UtcOffset::UTC))
    }

    pub(super) fn to_offset_date_time(self) -> OffsetDateTime {
        self.0
    }

    fn encode_text(self) -> String {
        let value = self.0;
        let mut text = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            value.year(),
            u8::from(value.month()),
            value.day(),
            value.hour(),
            value.minute(),
            value.second()
        );
        let nanosecond = value.nanosecond();
        if nanosecond != 0 {
            let fraction = format!("{nanosecond:09}");
            text.push('.');
            text.push_str(fraction.trim_end_matches('0'));
        }
        text.push('Z');
        text
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let (body, rest) = bytes.split_at_checked(14)?;
        if !body.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let digits = |range: std::ops::Range<usize>| -> Option<u32> {
            std::str::from_utf8(body.get(range)?).ok()?.parse().ok()
        };
        let year = i32::try_from(digits(0..4)?).ok()?;
        let month = Month::try_from(u8::try_from(digits(4..6)?).ok()?).ok()?;
        let day = u8::try_from(digits(6..8)?).ok()?;
        let hour = u8::try_from(digits(8..10)?).ok()?;
        let minute = u8::try_from(digits(10..12)?).ok()?;
        let second = u8::try_from(digits(12..14)?).ok()?;

        let nanosecond = match rest {
            [b'Z'] => 0,
            [b'.', fraction @ .., b'Z'] => {
                if fraction.is_empty()
                    || fraction.len() > MAX_FRACTION_DIGITS
                    || !fraction.iter().all(u8::is_ascii_digit)
                {
                    return None;
                }
                let scale = 10_u32.pow(u32::try_from(MAX_FRACTION_DIGITS - fraction.len()).ok()?);
                std::str::from_utf8(fraction).ok()?.parse::<u32>().ok()? * scale
            }
            _ => return None,
        };
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let time = Time::from_hms_nano(hour, minute, second, nanosecond).ok()?;
        Some(Self(PrimitiveDateTime::new(date, time).assume_utc()))
    }
}

impl FixedTag for TspGeneralizedTime {
    const TAG: Tag = Tag::GeneralizedTime;
}

impl<'a> DecodeValue<'a> for TspGeneralizedTime {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let length = usize::try_from(header.length)?;
        if !(SECONDS_FORM_LEN..=SECONDS_FORM_LEN + 1 + MAX_FRACTION_DIGITS).contains(&length) {
            return Err(Self::TAG.length_error());
        }
        let bytes = reader.read_vec(header.length)?;
        Self::parse(&bytes).ok_or_else(|| ErrorKind::DateTime.into())
    }
}

impl EncodeValue for TspGeneralizedTime {
    fn value_len(&self) -> der::Result<Length> {
        Length::try_from(self.encode_text().len())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(self.encode_text().as_bytes())
    }
}
