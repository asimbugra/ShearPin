//! minimal RLP decoder for unsigned legacy (EIP-155) EVM transactions
//! extracted from the payload bytes so the contract can derive amount + recipient
//! without trusting the agent's claimed amount.

use near_sdk::env;

/// Represents an unsigned legacy EVM transaction (RLP: [nonce, gasPrice, gasLimit, to, value, data])
#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedLegacyTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: String,          // "0x..." lowercase hex with 0x prefix
    pub value: u128,         // amount in wei
    pub data: Vec<u8>,       // calldata
}

/// RLP decoding errors — fail-closed on any malformed input
#[derive(Debug, Clone, PartialEq)]
pub enum RlpError {
    InvalidEncoding,
    InvalidLength,
    InvalidField,
    EmptyInput,
    ToAddressInvalid,
}

impl RlpError {
    /// Panic with SHEARPIN_* reason for contract deny events
    pub fn panic(self) -> ! {
        env::panic_str(&format!("SHEARPIN_RLP_ERROR: {:?}", self));
    }
}

/// Read a single RLP item (string or list) from `buf` starting at `offset`.
/// Returns (decoded_bytes, new_offset) where decoded_bytes is the raw item content
/// (for strings: the payload; for lists: the concatenated list items).
fn rlp_read_item(buf: &[u8], offset: usize) -> Result<(Vec<u8>, usize), RlpError> {
    if offset >= buf.len() {
        return Err(RlpError::InvalidEncoding);
    }
    let prefix = buf[offset];
    if prefix <= 0x7f {
        // single byte, value is the byte itself
        Ok((buf[offset..offset + 1].to_vec(), offset + 1))
    } else if prefix <= 0xb7 {
        // string 0-55 bytes
        let len = (prefix - 0x80) as usize;
        if offset + 1 + len > buf.len() {
            return Err(RlpError::InvalidLength);
        }
        let data = buf[offset + 1..offset + 1 + len].to_vec();
        Ok((data, offset + 1 + len))
    } else if prefix <= 0xbf {
        // string >55 bytes
        let len_of_len = (prefix - 0xb7) as usize;
        if offset + 1 + len_of_len > buf.len() {
            return Err(RlpError::InvalidLength);
        }
        let len_bytes = &buf[offset + 1..offset + 1 + len_of_len];
        let mut len_arr = [0u8; 8];
        for (i, &b) in len_bytes.iter().rev().enumerate() {
            if i >= 8 { return Err(RlpError::InvalidLength); }
            len_arr[7 - i] = b;
        }
        let len = u64::from_be_bytes(len_arr) as usize;
        if offset + 1 + len_of_len + len > buf.len() {
            return Err(RlpError::InvalidLength);
        }
        let data = buf[offset + 1 + len_of_len..offset + 1 + len_of_len + len].to_vec();
        Ok((data, offset + 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        // list 0-55 bytes
        let len = (prefix - 0xc0) as usize;
        if offset + 1 + len > buf.len() {
            return Err(RlpError::InvalidLength);
        }
        let data = buf[offset + 1..offset + 1 + len].to_vec();
        Ok((data, offset + 1 + len))
    } else {
        // list >55 bytes
        let len_of_len = (prefix - 0xf7) as usize;
        if offset + 1 + len_of_len > buf.len() {
            return Err(RlpError::InvalidLength);
        }
        let len_bytes = &buf[offset + 1..offset + 1 + len_of_len];
        let mut len_arr = [0u8; 8];
        for (i, &b) in len_bytes.iter().rev().enumerate() {
            if i >= 8 { return Err(RlpError::InvalidLength); }
            len_arr[7 - i] = b;
        }
        let len = u64::from_be_bytes(len_arr) as usize;
        if offset + 1 + len_of_len + len > buf.len() {
            return Err(RlpError::InvalidLength);
        }
        let data = buf[offset + 1 + len_of_len..offset + 1 + len_of_len + len].to_vec();
        Ok((data, offset + 1 + len_of_len + len))
    }
}

/// Decode a big-endian integer from RLP string item (no leading zeros except for zero itself)
fn rlp_decode_uint(bytes: &[u8]) -> Result<u128, RlpError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 16 {
        return Err(RlpError::InvalidField);
    }
    // reject leading zeros (canonical RLP)
    if bytes[0] == 0 {
        return Err(RlpError::InvalidField);
    }
    let mut val: u128 = 0;
    for &b in bytes {
        val = val.checked_shl(8).and_then(|v| v.checked_add(b as u128)).ok_or(RlpError::InvalidField)?;
    }
    Ok(val)
}

/// Decode a u64 from RLP string item
fn rlp_decode_u64(bytes: &[u8]) -> Result<u64, RlpError> {
    let val = rlp_decode_uint(bytes)?;
    if val > u64::MAX as u128 {
        return Err(RlpError::InvalidField);
    }
    Ok(val as u64)
}

/// Decode an Ethereum address (20 bytes) from RLP string item
fn rlp_decode_address(bytes: &[u8]) -> Result<String, RlpError> {
    if bytes.len() != 20 {
        return Err(RlpError::ToAddressInvalid);
    }
    // format as 0x + lowercase hex
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    Ok(s)
}

/// Parse the RLP-encoded unsigned legacy transaction (list of 6 items: nonce, gasPrice, gasLimit, to, value, data)
/// EIP-155: chain id is encoded in v, but unsigned tx has no v/r/s — just the 6 fields.
pub fn parse_unsigned_legacy_tx(payload: &[u8]) -> Result<UnsignedLegacyTx, RlpError> {
    // payload must be a single RLP list
    let (list_bytes, next) = rlp_read_item(payload, 0)?;
    if next != payload.len() {
        return Err(RlpError::InvalidEncoding);
    }

    // now parse the 6 items inside the list
    let mut offset = 0;
    let mut fields: Vec<Vec<u8>> = Vec::new();
    while offset < list_bytes.len() {
        let (item_bytes, new_offset) = rlp_read_item(&list_bytes, offset)?;
        fields.push(item_bytes);
        offset = new_offset;
    }

    if fields.len() != 6 {
        return Err(RlpError::InvalidEncoding);
    }

    let nonce = rlp_decode_u64(&fields[0])?;
    let gas_price = rlp_decode_uint(&fields[1])?;
    let gas_limit = rlp_decode_u64(&fields[2])?;
    let to = rlp_decode_address(&fields[3])?;
    let value = rlp_decode_uint(&fields[4])?;
    let data = fields[5].clone();

    Ok(UnsignedLegacyTx {
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// canonical test tx: nonce=1, gasPrice=20 gwei, gasLimit=21000,
    /// to=0xd4e56740f876afec8011e179a8b763074e6b5c8f, value=1 ETH, data=""
    fn canonical_rlp() -> Vec<u8> {
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);                                        // nonce=1
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);      // gasPrice=20e9 (5B)
        inner.extend([0x82, 0x52, 0x08]);                        // gasLimit=21000 (2B)
        inner.push(0x94);                                        // to: 20-byte string
        inner.extend([0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xaf, 0xec, 0x80, 0x11,
                      0xe1, 0x79, 0xa8, 0xb7, 0x63, 0x07, 0x4e, 0x6b, 0x5c, 0x8f]);
        inner.extend([0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]); // value=1e18 (8B)
        inner.push(0x80);                                        // data=""
        // outer list: 1+6+3+21+9+1 = 41 bytes payload -> prefix 0xc0+41 = 0xe9
        let mut rlp = vec![0xc0 + inner.len() as u8];
        rlp.extend(inner);
        rlp
    }

    #[test]
    fn rlp_single_byte() {
        let buf = [0x05u8];
        let (data, off) = rlp_read_item(&buf, 0).unwrap();
        assert_eq!(data, vec![0x05]);
        assert_eq!(off, 1);
    }

    #[test]
    fn rlp_short_string() {
        // "cat" = 0x83 63 61 74
        let buf = [0x83, 0x63, 0x61, 0x74];
        let (data, off) = rlp_read_item(&buf, 0).unwrap();
        assert_eq!(data, b"cat");
        assert_eq!(off, 4);
    }

    #[test]
    fn rlp_short_list() {
        // list of two empty strings: 0xc2 0x80 0x80
        let buf = [0xc2, 0x80, 0x80];
        let (data, off) = rlp_read_item(&buf, 0).unwrap();
        assert_eq!(data, vec![0x80, 0x80]);
        assert_eq!(off, 3);
    }

    #[test]
    fn parse_legacy_tx_happy() {
        let rlp = canonical_rlp();
        let tx = parse_unsigned_legacy_tx(&rlp).unwrap();
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.gas_price, 20_000_000_000);
        assert_eq!(tx.gas_limit, 21_000);
        assert_eq!(tx.to, "0xd4e56740f876afec8011e179a8b763074e6b5c8f");
        assert_eq!(tx.value, 1_000_000_000_000_000_000);
        assert!(tx.data.is_empty());
    }

    #[test]
    fn parse_legacy_tx_wrong_field_count() {
        // list of 5 items instead of 6
        let rlp = vec![0xc5, 0x01, 0x80, 0x80, 0x94, 0x00, 0x80, 0x80];
        assert!(parse_unsigned_legacy_tx(&rlp).is_err());
    }

    #[test]
    fn parse_legacy_tx_invalid_to_length() {
        // to field is 19 bytes instead of 20
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);
        inner.extend([0x82, 0x52, 0x08]);
        inner.push(0x93); // 19 bytes! (should be 0x94 for 20)
        inner.extend([0u8; 19]);
        inner.extend([0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]);
        inner.push(0x80);
        let mut rlp = vec![0xc0 + inner.len() as u8];
        rlp.extend(inner);
        assert!(matches!(parse_unsigned_legacy_tx(&rlp), Err(RlpError::ToAddressInvalid)));
    }

    #[test]
    fn rlp_decode_uint_rejects_leading_zeros() {
        // "00 01" should fail
        let bytes = [0x00, 0x01];
        assert!(rlp_decode_uint(&bytes).is_err());
    }

    #[test]
    fn rlp_decode_address_valid() {
        let bytes = [0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xaf, 0xec, 0x80, 0x11, 0xe1, 0x79, 0xa8, 0xb7, 0x63, 0x07, 0x4e, 0x6b, 0x5c, 0x8f];
        let addr = rlp_decode_address(&bytes).unwrap();
        assert_eq!(addr, "0xd4e56740f876afec8011e179a8b763074e6b5c8f");
    }
}