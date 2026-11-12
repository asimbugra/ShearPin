//! minimal RLP decoder for unsigned EVM transactions (legacy + EIP-155)
//! extracted from the payload bytes so the contract can derive amount + recipient
//! without trusting the agent's claimed amount.
//!
//! supported formats:
//!   - legacy (6 fields): [nonce, gasPrice, gasLimit, to, value, data]
//!   - EIP-155 (9 fields): [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
//!
//! calldata policy: empty data = native transfer. non-empty data MUST be a known
//! ERC-20 transfer (selector 0xa9059cbb) to an allowlisted address. anything
//! else is rejected fail-closed.

use near_sdk::env;

/// ERC-20 transfer selector: keccak256("transfer(address,uint256)") = 0xa9059cbb
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Represents an unsigned EVM transaction (legacy or EIP-155)
#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedEvmTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: String,              // "0x..." lowercase hex with 0x prefix
    pub value: u128,             // native value in wei
    pub data: Vec<u8>,           // calldata
    pub chain_id: Option<u64>,   // Some(chain_id) for EIP-155, None for legacy
    // derived ERC-20 fields (if data is ERC-20 transfer)
    pub erc20_to: Option<String>,
    pub erc20_amount: Option<u128>,
}

/// RLP decoding errors — fail-closed on any malformed input
#[derive(Debug, Clone, PartialEq)]
pub enum RlpError {
    InvalidEncoding,
    InvalidLength,
    InvalidField,
    EmptyInput,
    ToAddressInvalid,
    UnknownCalldata,
    InvalidErc20Calldata,
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

/// decode a u128 from a fixed 32-byte big-endian calldata word.
/// unlike rlp_decode_uint this tolerates leading zeros (calldata words
/// are always 32 bytes, zero-padded).
fn decode_u128_word(bytes: &[u8]) -> Result<u128, RlpError> {
    if bytes.len() != 32 {
        return Err(RlpError::InvalidErc20Calldata);
    }
    // find first non-zero byte
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    let significant = &bytes[start..];
    if significant.len() > 16 {
        return Err(RlpError::InvalidField);
    }
    let mut val: u128 = 0;
    for &b in significant {
        val = val
            .checked_shl(8)
            .and_then(|v| v.checked_add(b as u128))
            .ok_or(RlpError::InvalidField)?;
    }
    Ok(val)
}

/// Parse ERC-20 transfer calldata: selector(4) + to(32) + amount(32)
/// returns (to_address, amount) if valid
fn parse_erc20_transfer(data: &[u8]) -> Result<(String, u128), RlpError> {
    // selector check FIRST — unknown selectors are rejected regardless of length
    if data.len() < 4 || data[0..4] != ERC20_TRANSFER_SELECTOR {
        return Err(RlpError::UnknownCalldata);
    }
    // must be at least 4 + 32 + 32 = 68 bytes
    if data.len() < 68 {
        return Err(RlpError::InvalidErc20Calldata);
    }
    // to address is at bytes 4+12..4+32 (last 20 bytes of the 32-byte word)
    let to_bytes = &data[4 + 12..4 + 32];
    if to_bytes.len() != 20 {
        return Err(RlpError::InvalidErc20Calldata);
    }
    // amount is at bytes 36..68 (32 bytes, big-endian, zero-padded)
    let amount = decode_u128_word(&data[36..68])?;

    // format to address
    let mut to = String::with_capacity(42);
    to.push_str("0x");
    for &b in to_bytes {
        to.push_str(&format!("{:02x}", b));
    }

    Ok((to, amount))
}

/// Parse the RLP-encoded unsigned EVM transaction
/// supports both legacy (6 fields) and EIP-155 (9 fields) formats
pub fn parse_unsigned_evm_tx(payload: &[u8]) -> Result<UnsignedEvmTx, RlpError> {
    // payload must be a single RLP list
    let (list_bytes, next) = rlp_read_item(payload, 0)?;
    if next != payload.len() {
        return Err(RlpError::InvalidEncoding);
    }

    // now parse the fields inside the list
    let mut offset = 0;
    let mut fields: Vec<Vec<u8>> = Vec::new();
    while offset < list_bytes.len() {
        let (item_bytes, new_offset) = rlp_read_item(&list_bytes, offset)?;
        fields.push(item_bytes);
        offset = new_offset;
    }

    // accept 6 (legacy) or 9 (EIP-155) fields
    if fields.len() != 6 && fields.len() != 9 {
        return Err(RlpError::InvalidEncoding);
    }

    let nonce = rlp_decode_u64(&fields[0])?;
    let gas_price = rlp_decode_uint(&fields[1])?;
    let gas_limit = rlp_decode_u64(&fields[2])?;
    let to = rlp_decode_address(&fields[3])?;
    let value = rlp_decode_uint(&fields[4])?;
    let data = fields[5].clone();

    // chain_id: field 6 for EIP-155 (fields[6]), None for legacy
    let chain_id = if fields.len() == 9 {
        Some(rlp_decode_u64(&fields[6])?)
    } else {
        None
    };

    // validate EIP-155 fields 7 & 8 are empty (0, 0)
    if fields.len() == 9 {
        if !fields[7].is_empty() || !fields[8].is_empty() {
            return Err(RlpError::InvalidField);
        }
    }

    // calldata validation: empty = native transfer OK
    // non-empty = must be ERC-20 transfer to allowlisted address (checked in contract)
    let (erc20_to, erc20_amount) = if data.is_empty() {
        (None, None)
    } else {
        match parse_erc20_transfer(&data) {
            Ok((to, amt)) => (Some(to), Some(amt)),
            Err(RlpError::UnknownCalldata) => return Err(RlpError::UnknownCalldata),
            Err(e) => return Err(e),
        }
    };

    Ok(UnsignedEvmTx {
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        chain_id,
        erc20_to,
        erc20_amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// canonical legacy tx: nonce=1, gasPrice=20 gwei, gasLimit=21000,
    /// to=0xd4e56740f876afec8011e179a8b763074e6b5c8f, value=1 ETH, data=""
    fn canonical_legacy_rlp() -> Vec<u8> {
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);                                        // nonce=1
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);      // gasPrice=20e9 (5B)
        inner.extend([0x82, 0x52, 0x08]);                        // gasLimit=21000 (2B)
        inner.push(0x94);                                        // to: 20-byte string
        inner.extend([0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xaf, 0xec, 0x80, 0x11,
                      0xe1, 0x79, 0xa8, 0xb7, 0x63, 0x07, 0x4e, 0x6b, 0x5c, 0x8f]);
        inner.extend([0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]); // value=1e18 (8B)
        inner.push(0x80);                                        // data=""
        let mut rlp = vec![0xc0 + inner.len() as u8];
        rlp.extend(inner);
        rlp
    }

    /// EIP-155 tx: same as legacy but with chainId=11155111 (Sepolia), 0, 0
    fn canonical_eip155_rlp() -> Vec<u8> {
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);                                        // nonce=1
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);      // gasPrice=20e9
        inner.extend([0x82, 0x52, 0x08]);                        // gasLimit=21000
        inner.push(0x94);                                        // to: 20-byte string
        inner.extend([0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xaf, 0xec, 0x80, 0x11,
                      0xe1, 0x79, 0xa8, 0xb7, 0x63, 0x07, 0x4e, 0x6b, 0x5c, 0x8f]);
        inner.extend([0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]); // value=1e18
        inner.push(0x80);                                        // data=""
        // chainId = 11155111 (0xaa36a7) -> 0x83 aa 36 a7
        inner.extend([0x83, 0xaa, 0x36, 0xa7]);
        inner.push(0x80); // 0
        inner.push(0x80); // 0
        let mut rlp = vec![0xc0 + inner.len() as u8];
        rlp.extend(inner);
        rlp
    }

    /// ERC-20 transfer calldata: transfer(0xRecipient, 12345)
    fn erc20_transfer_calldata(to: &str, amount: u128) -> Vec<u8> {
        let to = to.strip_prefix("0x").unwrap_or(to);
        let mut data = ERC20_TRANSFER_SELECTOR.to_vec();
        // to: 32 bytes, right-aligned (12 zeros + 20 bytes address)
        data.extend([0u8; 12]);
        for i in (0..to.len()).step_by(2) {
            data.push(u8::from_str_radix(&to[i..i+2], 16).unwrap());
        }
        // amount: 32 bytes big-endian
        let mut amt_bytes = [0u8; 32];
        let mut v = amount;
        for i in (0..32).rev() {
            amt_bytes[i] = (v & 0xff) as u8;
            v >>= 8;
        }
        data.extend(amt_bytes);
        data
    }

    fn erc20_rlp(to: &str, amount: u128) -> Vec<u8> {
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);                                        // nonce=1
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);      // gasPrice=20e9
        inner.extend([0x82, 0x52, 0x08]);                        // gasLimit=21000
        // to = token contract address (e.g., USDC)
        inner.push(0x94);
        inner.extend([0xa0, 0xb8, 0x6a, 0x33, 0xe7, 0x4c, 0x7c, 0x5c, 0x1e, 0x2b,
                      0x8f, 0x1e, 0x3d, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x00]);
        inner.push(0x80);                                        // value=0
        let calldata = erc20_transfer_calldata(to, amount);
        // data length prefix
        if calldata.len() <= 55 {
            inner.push(0x80 + calldata.len() as u8);
        } else {
            let mut lb = vec![];
            let mut l = calldata.len();
            while l > 0 { lb.insert(0, (l & 0xff) as u8); l >>= 8; }
            inner.push(0xb7 + lb.len() as u8);
            inner.extend(lb);
        }
        inner.extend(calldata);
        let len = inner.len();
        let mut rlp = vec![];
        if len <= 55 {
            rlp.push(0xc0 + len as u8);
        } else {
            let mut lb = vec![];
            let mut l = len;
            while l > 0 { lb.insert(0, (l & 0xff) as u8); l >>= 8; }
            rlp.push(0xf7 + lb.len() as u8);
            rlp.extend(lb);
        }
        rlp.extend(inner);
        rlp
    }

    #[test]
    fn parse_legacy_tx_happy() {
        let rlp = canonical_legacy_rlp();
        let tx = parse_unsigned_evm_tx(&rlp).unwrap();
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.gas_price, 20_000_000_000);
        assert_eq!(tx.gas_limit, 21_000);
        assert_eq!(tx.to, "0xd4e56740f876afec8011e179a8b763074e6b5c8f");
        assert_eq!(tx.value, 1_000_000_000_000_000_000);
        assert!(tx.data.is_empty());
        assert_eq!(tx.chain_id, None);
        assert!(tx.erc20_to.is_none());
    }

    #[test]
    fn parse_eip155_tx_happy() {
        let rlp = canonical_eip155_rlp();
        let tx = parse_unsigned_evm_tx(&rlp).unwrap();
        assert_eq!(tx.chain_id, Some(11155111));
        assert!(tx.data.is_empty());
    }

    #[test]
    fn parse_erc20_transfer_happy() {
        let rlp = erc20_rlp("0xd4e56740f876afec8011e179a8b763074e6b5c8f", 1_000_000);
        let tx = parse_unsigned_evm_tx(&rlp).unwrap();
        assert_eq!(tx.value, 0);
        assert_eq!(tx.erc20_to, Some("0xd4e56740f876afec8011e179a8b763074e6b5c8f".to_string()));
        assert_eq!(tx.erc20_amount, Some(1_000_000));
    }

    #[test]
    fn unknown_calldata_rejected() {
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);
        inner.extend([0x82, 0x52, 0x08]);
        inner.push(0x94);
        inner.extend([0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xaf, 0xec, 0x80, 0x11, 0xe1, 0x79, 0xa8, 0xb7, 0x63, 0x07, 0x4e, 0x6b, 0x5c, 0x8f]);
        inner.push(0x80); // value=0
        // unknown selector 0xdeadbeef + 64 bytes
        inner.push(0xb8);
        inner.push(44);
        inner.extend([0xde, 0xad, 0xbe, 0xef]);
        inner.extend([0u8; 40]);
        let len = inner.len();
        let mut rlp = vec![];
        if len <= 55 {
            rlp.push(0xc0 + len as u8);
        } else {
            let mut lb = vec![];
            let mut l = len;
            while l > 0 { lb.insert(0, (l & 0xff) as u8); l >>= 8; }
            rlp.push(0xf7 + lb.len() as u8);
            rlp.extend(lb);
        }
        rlp.extend(inner);
        assert!(matches!(parse_unsigned_evm_tx(&rlp), Err(RlpError::UnknownCalldata)));
    }

    #[test]
    fn malformed_erc20_calldata_rejected() {
        let rlp = erc20_rlp("0xd4e56740f876afec8011e179a8b763074e6b5c8f", 1_000_000);
        // corrupt the selector: outer prefix is 2 bytes ([0xf8, 0x65]);
        // calldata starts at offset 2+34 = 36, selector = bytes 36..40
        let mut bad = rlp.clone();
        bad[36] = 0x00;
        assert!(matches!(parse_unsigned_evm_tx(&bad), Err(RlpError::UnknownCalldata)));
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
        let buf = [0x83, 0x63, 0x61, 0x74];
        let (data, off) = rlp_read_item(&buf, 0).unwrap();
        assert_eq!(data, b"cat");
        assert_eq!(off, 4);
    }

    #[test]
    fn rlp_short_list() {
        let buf = [0xc2, 0x80, 0x80];
        let (data, off) = rlp_read_item(&buf, 0).unwrap();
        assert_eq!(data, vec![0x80, 0x80]);
        assert_eq!(off, 3);
    }

    #[test]
    fn parse_legacy_tx_wrong_field_count() {
        let rlp = vec![0xc5, 0x01, 0x80, 0x80, 0x94, 0x00, 0x80, 0x80];
        assert!(parse_unsigned_evm_tx(&rlp).is_err());
    }

    #[test]
    fn parse_legacy_tx_invalid_to_length() {
        let mut inner: Vec<u8> = vec![];
        inner.push(0x01);
        inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);
        inner.extend([0x82, 0x52, 0x08]);
        inner.push(0x93); // 19 bytes!
        inner.extend([0u8; 19]);
        inner.extend([0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]);
        inner.push(0x80);
        let mut rlp = vec![0xc0 + inner.len() as u8];
        rlp.extend(inner);
        assert!(matches!(parse_unsigned_evm_tx(&rlp), Err(RlpError::ToAddressInvalid)));
    }

    #[test]
    fn rlp_decode_uint_rejects_leading_zeros() {
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