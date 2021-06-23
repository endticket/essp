use rand::{Rng, OsRng};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use std::io::Cursor;
use std::iter;
use std::convert;
use std::string::FromUtf8Error;
use std::fmt;
use crypto::{aessafe, blockmodes};
use crypto::symmetriccipher::{Encryptor, Decryptor, SymmetricCipherError};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult};

const STX: u8 = 0x7Fu8;
const STEX: u8 = 0x7Eu8;
const MAX_SLAVE_ID: u8 = 0x7Du8;

pub type SlaveID = u8;
pub type Data = Vec<u8>;
pub type DataSlice = [u8];
pub type CRC = [u8; 2];
pub type ECount = u32;
pub type Generator = u64;
pub type Modulus = u64;
pub type InterKey = u64;
pub type Key = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Command {
    // Generic Commands
    Reset,
    HostProtocolVersion,
    GetSerialNumber,
    Sync,
    Disable,
    Enable,
    GetFirmwareVersion,
    GetDatasetVersion,
    // Smart Hopper Commands
    PayoutAmount,
    GetDenominationLevel,
    HaltPayout,
    GetDenominationRoute,
    GetMinimumPayout,
    SetCoinMechInhibits,
    PayoutByDenomination,
    SetGenerator,
    RequestKeyExchange,
    GetBuildRevision,
    GetHopperOptions,
    CashboxPayoutOperationData,
    EventAck,
    SetFixedEncryptionKey,
    SetupRequest,
    Poll,
    GetAllLevels,
    SetDenominationLevel,
    CommunicationPassThrough,
    SetDenominatinoRoute,
    FloatAmount,
    EmptyAll,
    FloatByDenomination,
    SetCoinMechGlobalInhibit,
    SetModulus,
    SetBaudRate,
    SetHopperOptions,
    SmartEmpty,
    PollWithAck,
    CoinMechOptions,
    ResetFixedEncryptionKey,
    SetCashboxPayoutLimit,
    // NV9 USB bill validator commands
    SetInhibits,
    DisplayOn,
    DisplayOff,
    Reject,
    UintData,
    ChannelValueData,
    ChannelSecurityData,
    LastRejectCode,
    Hold,
    GetCounters,
    ResetCounters,
    Unknown(u8),
}

impl Command {
    #[allow(dead_code)]
    pub fn from_u8(n: u8) -> Command {
        match n {
            0x01 => Command::Reset,
            0x06 => Command::HostProtocolVersion,
            0x0C => Command::GetSerialNumber,
            0x11 => Command::Sync,
            0x09 => Command::Disable,
            0x0A => Command::Enable,
            0x20 => Command::GetFirmwareVersion,
            0x21 => Command::GetDatasetVersion,
            0x33 => Command::PayoutAmount,
            0x35 => Command::GetDenominationLevel,
            0x38 => Command::HaltPayout,
            0x3C => Command::GetDenominationRoute,
            0x3E => Command::GetMinimumPayout,
            0x40 => Command::SetCoinMechInhibits,
            0x46 => Command::PayoutByDenomination,
            0x4A => Command::SetGenerator,
            0x4C => Command::RequestKeyExchange,
            0x4F => Command::GetBuildRevision,
            0x51 => Command::GetHopperOptions,
            0x53 => Command::CashboxPayoutOperationData,
            0x57 => Command::EventAck,
            0x60 => Command::SetFixedEncryptionKey,
            0x05 => Command::SetupRequest,
            0x07 => Command::Poll,
            0x22 => Command::GetAllLevels,
            0x34 => Command::SetDenominationLevel,
            0x37 => Command::CommunicationPassThrough,
            0x3B => Command::SetDenominatinoRoute,
            0x3D => Command::FloatAmount,
            0x3F => Command::EmptyAll,
            0x44 => Command::FloatByDenomination,
            0x49 => Command::SetCoinMechGlobalInhibit,
            0x4B => Command::SetModulus,
            0x4D => Command::SetBaudRate,
            0x50 => Command::SetHopperOptions,
            0x52 => Command::SmartEmpty,
            0x56 => Command::PollWithAck,
            0x5A => Command::CoinMechOptions,
            0x61 => Command::ResetFixedEncryptionKey,
            0x4E => Command::SetCashboxPayoutLimit,
            0x02 => Command::SetInhibits,
            0x03 => Command::DisplayOn,
            0x04 => Command::DisplayOff,
            0x08 => Command::Reject,
            0x0D => Command::UintData,
            0x0E => Command::ChannelValueData,
            0x0F => Command::ChannelSecurityData,
            0x17 => Command::LastRejectCode,
            0x18 => Command::Hold,
            0x58 => Command::GetCounters,
            0x59 => Command::ResetCounters,
            _ => Command::Unknown(n),
        }
    }

    #[allow(dead_code)]
    pub fn to_u8(&self) -> u8 {
        match *self {
            Command::Reset => 0x01,
            Command::HostProtocolVersion => 0x06,
            Command::GetSerialNumber => 0x0C,
            Command::Sync => 0x11,
            Command::Disable => 0x09,
            Command::Enable => 0x0A,
            Command::GetFirmwareVersion => 0x20,
            Command::GetDatasetVersion => 0x21,
            Command::PayoutAmount => 0x33,
            Command::GetDenominationLevel => 0x35,
            Command::HaltPayout => 0x38,
            Command::GetDenominationRoute => 0x3C,
            Command::GetMinimumPayout => 0x3E,
            Command::SetCoinMechInhibits => 0x40,
            Command::PayoutByDenomination => 0x46,
            Command::SetGenerator => 0x4A,
            Command::RequestKeyExchange => 0x4C,
            Command::GetBuildRevision => 0x4F,
            Command::GetHopperOptions => 0x51,
            Command::CashboxPayoutOperationData => 0x53,
            Command::EventAck => 0x57,
            Command::SetFixedEncryptionKey => 0x60,
            Command::SetupRequest => 0x05,
            Command::Poll => 0x07,
            Command::GetAllLevels => 0x22,
            Command::SetDenominationLevel => 0x34,
            Command::CommunicationPassThrough => 0x37,
            Command::SetDenominatinoRoute => 0x3B,
            Command::FloatAmount => 0x3D,
            Command::EmptyAll => 0x3F,
            Command::FloatByDenomination => 0x44,
            Command::SetCoinMechGlobalInhibit => 0x49,
            Command::SetModulus => 0x4B,
            Command::SetBaudRate => 0x4D,
            Command::SetHopperOptions => 0x50,
            Command::SmartEmpty => 0x52,
            Command::PollWithAck => 0x56,
            Command::CoinMechOptions => 0x5A,
            Command::ResetFixedEncryptionKey => 0x61,
            Command::SetCashboxPayoutLimit => 0x4E,
            Command::SetInhibits => 0x02,
            Command::DisplayOn => 0x03,
            Command::DisplayOff => 0x04,
            Command::Reject => 0x08,
            Command::UintData => 0x0D,
            Command::ChannelValueData => 0x0E,
            Command::ChannelSecurityData => 0x0F,
            Command::LastRejectCode => 0x17,
            Command::Hold => 0x18,
            Command::GetCounters => 0x58,
            Command::ResetCounters => 0x59,
            Command::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Response {
    Ok,
    CommandNotKnown,
    WrongNumberOfParameters,
    ParameterOutOfRange,
    CommandCannotBeProcessed,
    SoftwareError,
    Fail,
    KeyNotSet,
    Unknown(u8),
}

impl Response {
    #[allow(dead_code)]
    pub fn from_u8(n: u8) -> Response {
        match n {
            0xF0 => Response::Ok,
            0xF2 => Response::CommandNotKnown,
            0xF3 => Response::WrongNumberOfParameters,
            0xF4 => Response::ParameterOutOfRange,
            0xF5 => Response::CommandCannotBeProcessed,
            0xF6 => Response::SoftwareError,
            0xF8 => Response::Fail,
            0xFA => Response::KeyNotSet,
            _ => Response::Unknown(n),
        }
    }

    #[allow(dead_code)]
    pub fn to_u8(&self) -> u8 {
        match *self {
            Response::Ok => 0xF0,
            Response::CommandNotKnown => 0xF2,
            Response::WrongNumberOfParameters => 0xF3,
            Response::ParameterOutOfRange => 0xF4,
            Response::CommandCannotBeProcessed => 0xF5,
            Response::SoftwareError => 0xF6,
            Response::Fail => 0xF8,
            Response::KeyNotSet => 0xFA,
            Response::Unknown(n) => n,
        }
    }
}


#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ErrorType {
    NotAResponse,
    PartialMessage,
    CRCError,
    EncryptedCRCError,
    SlaveIdError,
    NoResponse,
    UnknownResponse,
    KeyNotSet,
    UTF8Error,
    KeyExchangeError,
    CryptoError(SymmetricCipherError),
    EncryptionCounterError,
    NotOkResponse(Payload),
    ParseError,
}

impl convert::From<SymmetricCipherError> for ErrorType {
    fn from(e: SymmetricCipherError) -> ErrorType {
        ErrorType::CryptoError(e)
    }
}

impl convert::From<FromUtf8Error> for ErrorType {
    fn from(_: FromUtf8Error) -> ErrorType {
        ErrorType::UTF8Error
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Code {
    CommandCode(Command),
    ResponseCode(Response),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CoinValue {
    pub value: u32,
    pub country_code: String,
}

impl CoinValue {
    pub fn decode(data: &mut Vec<u8>) -> Result<CoinValue, ErrorType> {
        let value_vec: Vec<u8> = data.drain(0..4 as usize).collect();
        let country_code_vec: Vec<u8> = data.drain(0..3 as usize).collect();

        let country_code = String::from_utf8(country_code_vec)?;

        let val = vec_to_u32(&value_vec)?;

        Ok(CoinValue {
               value: val,
               country_code: country_code,
           })
    }

    pub fn decode_list(data: &mut Vec<u8>) -> Result<Vec<CoinValue>, ErrorType> {
        let num = data.remove(0);
        let mut coin_values = Vec::<CoinValue>::new();
        for _ in 0..num {
            coin_values.push(CoinValue::decode(data)?);
        }
        Ok(coin_values)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = vec![];
        let mut value_vec = u32_to_vec(self.value);
        data.append(&mut value_vec);
        data.extend_from_slice(self.country_code.as_bytes());

        data
    }

    pub fn encode_list(list: &Vec<CoinValue>) -> Vec<u8> {
        let mut data = vec![list.len() as u8];

        for elem in list {
            let mut elem_data = elem.encode();
            data.append(&mut elem_data);
        }
        data
    }
}

impl fmt::Display for CoinValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.value, self.country_code)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CoinNumValue {
    pub num: u16,
    pub value: u32,
    pub country_code: String,
}

impl CoinNumValue {
    pub fn decode(data: &mut Vec<u8>) -> Result<CoinNumValue, ErrorType> {
        let num_vec: Vec<u8> = data.drain(0..2 as usize).collect();
        let value_vec: Vec<u8> = data.drain(0..4 as usize).collect();
        let country_code_vec: Vec<u8> = data.drain(0..3 as usize).collect();

        let country_code = String::from_utf8(country_code_vec)?;

        let num = vec_to_u16(&num_vec)?;
        let val = vec_to_u32(&value_vec)?;

        Ok(CoinNumValue {
               num: num,
               value: val,
               country_code: country_code,
           })
    }

    pub fn decode_list(data: &mut Vec<u8>) -> Result<Vec<CoinNumValue>, ErrorType> {
        let num = data.remove(0);
        let mut coin_num_values = Vec::<CoinNumValue>::new();
        for _ in 0..num {
            coin_num_values.push(CoinNumValue::decode(data)?);
        }
        Ok(coin_num_values)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = vec![];
        let mut num_vec = u16_to_vec(self.num);
        data.append(&mut num_vec);
        let mut value_vec = u32_to_vec(self.value);
        data.append(&mut value_vec);
        data.extend_from_slice(self.country_code.as_bytes());

        data
    }

    pub fn encode_list(list: &Vec<CoinNumValue>) -> Vec<u8> {
        let mut data = vec![list.len() as u8];

        for elem in list {
            let mut elem_data = elem.encode();
            data.append(&mut elem_data);
        }
        data
    }
}

impl fmt::Display for CoinNumValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}: {}", self.value, self.country_code, self.num)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct IncompleteCoinValue {
    pub value: u32,
    pub value_requested: u32,
    pub country_code: String,
}

impl IncompleteCoinValue {
    pub fn decode(data: &mut Vec<u8>) -> Result<IncompleteCoinValue, ErrorType> {
        let value_vec: Vec<u8> = data.drain(0..4 as usize).collect();
        let value_requested_vec: Vec<u8> = data.drain(0..4 as usize).collect();
        let country_code_vec: Vec<u8> = data.drain(0..3 as usize).collect();

        let country_code = String::from_utf8(country_code_vec)?;

        let val = vec_to_u32(&value_vec)?;
        let val_req = vec_to_u32(&value_requested_vec)?;

        Ok(IncompleteCoinValue {
               value: val,
               value_requested: val_req,
               country_code: country_code,
           })
    }

    pub fn decode_list(data: &mut Vec<u8>) -> Result<Vec<IncompleteCoinValue>, ErrorType> {
        let num = data.remove(0);
        let mut coin_values = Vec::<IncompleteCoinValue>::new();
        for _ in 0..num {
            coin_values.push(IncompleteCoinValue::decode(data)?);
        }
        Ok(coin_values)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = vec![];
        let mut value_vec = u32_to_vec(self.value);
        data.append(&mut value_vec);
        let mut value_vec_req = u32_to_vec(self.value_requested);
        data.append(&mut value_vec_req);
        data.extend_from_slice(self.country_code.as_bytes());

        data
    }

    pub fn encode_list(list: &Vec<IncompleteCoinValue>) -> Vec<u8> {
        let mut data = vec![list.len() as u8];

        for elem in list {
            let mut elem_data = elem.encode();
            data.append(&mut elem_data);
        }
        data
    }
}



#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CashboxPayoutData {
    pub known: Vec<CoinNumValue>,
    pub unknown: u32,
}

impl CashboxPayoutData {
    pub fn decode(data: &mut Vec<u8>) -> Result<CashboxPayoutData, ErrorType> {
        let known = CoinNumValue::decode_list(data)?;
        let unknown_vec: Vec<u8> = data.drain(0..4 as usize).collect();
        let unknown = vec_to_u32(&unknown_vec)?;

        Ok(CashboxPayoutData {
               known: known,
               unknown: unknown,
           })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = vec![];
        let mut known = CoinNumValue::encode_list(&self.known);
        data.append(&mut known);

        let mut unknown_vec = u32_to_vec(self.unknown);
        data.append(&mut unknown_vec);

        data
    }
}



#[derive(Debug)]
#[derive(Clone)]
#[allow(dead_code)]
pub enum DeviceType {
    BillValidator,
    SmartHopper,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FraudAttemptData {
    BillValidatorData { channel: u8 },
    SmartHopperData { dispensed: Vec<CoinValue> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PollEvent {
    SlaveReset,
    Disabled,
    FraudAttempt { data: FraudAttemptData },
    Initialising,
    Dispensing { dispensed: Vec<CoinValue> },
    Dispensed { dispensed: Vec<CoinValue> },
    CoinsLow,
    HopperJammed { dispensed: Vec<CoinValue> },
    Halted { dispensed: Vec<CoinValue> },
    Floating { floated: Vec<CoinValue> },
    Floated { floated: Vec<CoinValue> },
    Timeout { dispensed: Vec<CoinValue> },
    IncompletePayout { dispensed: Vec<IncompleteCoinValue> },
    IncompleteFloat { floated: Vec<IncompleteCoinValue> },
    CashboxPaid { dispensed: Vec<CoinValue> },
    CoinCredit { credit: CoinValue },
    CoinMechJammed,
    CoinMechReturnActive,
    Emptying,
    Emptied,
    SmartEmptying { dispensed: Vec<CoinValue> },
    SmartEmptied { dispensed: Vec<CoinValue> },
    CalibrationFailed { error_code: u8 },
    CoinMechError { error_code: u8 },
    AttachedCoinMechDisabled,
    AttachedCoinMechEnabled,
    Read { channel: u8 },
    NoteCredit { channel: u8 },
    Rejecting,
    Rejected,
    Stacking,
    Stacked,
    SafeJam,
    UnsafeJam,
    StackerFull,
    NoteClearedFromFront { channel: u8 },
    NoteClearedIntoCashbox { channel: u8 },
    ChannelDisable,
    TicketInBezel,
    PrintedToCashbox,
    Unknown(u8),
}

impl PollEvent {
    #[allow(dead_code)]
    pub fn parse_first(data: &mut Vec<u8>, device_type: &DeviceType) -> Result<Option<PollEvent>, ErrorType> {

        // Note: it's parsing poll response as ESSP ver6

        if data.len() == 0 {
            return Ok(None);
        }
        let code = data.remove(0);
        match code {
            0xF1 => Ok(Some(PollEvent::SlaveReset)),
            0xE8 => Ok(Some(PollEvent::Disabled)),
            0xE6 => {
                match device_type {
                    &DeviceType::BillValidator => {
                        let channel = data.remove(0);
                        Ok(Some(PollEvent::FraudAttempt { data: FraudAttemptData::BillValidatorData { channel: channel } }))
                    }
                    &DeviceType::SmartHopper => {
                        let coin_values = CoinValue::decode_list(data)?;
                        Ok(Some(PollEvent::FraudAttempt { data: FraudAttemptData::SmartHopperData { dispensed: coin_values } }))
                    }
                }
            }
            0xB6 => Ok(Some(PollEvent::Initialising)),
            0xDA => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::Dispensing { dispensed: coin_values }))
            }
            0xD2 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::Dispensed { dispensed: coin_values }))
            }
            0xD3 => Ok(Some(PollEvent::CoinsLow)),
            0xD5 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::HopperJammed { dispensed: coin_values }))
            }
            0xD6 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::Halted { dispensed: coin_values }))
            }
            0xD7 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::Floating { floated: coin_values }))
            }
            0xD8 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::Floated { floated: coin_values }))
            }
            0xD9 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::Timeout { dispensed: coin_values }))
            }
            0xDC => {
                let coin_values = IncompleteCoinValue::decode_list(data)?;
                Ok(Some(PollEvent::IncompletePayout { dispensed: coin_values }))
            }
            0xDD => {
                let coin_values = IncompleteCoinValue::decode_list(data)?;
                Ok(Some(PollEvent::IncompleteFloat { floated: coin_values }))
            }
            0xDE => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::CashboxPaid { dispensed: coin_values }))
            }
            0xDF => {
                let coin_value = CoinValue::decode(data)?;
                Ok(Some(PollEvent::CoinCredit { credit: coin_value }))
            }
            0xC4 => Ok(Some(PollEvent::CoinMechJammed)),
            0xC5 => Ok(Some(PollEvent::CoinMechReturnActive)),
            0xC2 => Ok(Some(PollEvent::Emptying)),
            0xC3 => Ok(Some(PollEvent::Emptied)),
            0xB3 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::SmartEmptying { dispensed: coin_values }))
            }
            0xB4 => {
                let coin_values = CoinValue::decode_list(data)?;
                Ok(Some(PollEvent::SmartEmptied { dispensed: coin_values }))
            }
            0x83 => {
                let error_code = data.remove(0);
                Ok(Some(PollEvent::CalibrationFailed { error_code: error_code }))
            }
            0xB7 => {
                let error_code = data.remove(0);
                Ok(Some(PollEvent::CoinMechError { error_code: error_code }))
            }
            0xBD => Ok(Some(PollEvent::AttachedCoinMechDisabled)),
            0xBE => Ok(Some(PollEvent::AttachedCoinMechEnabled)),
            0xEF => {
                let channel = data.remove(0);
                Ok(Some(PollEvent::Read { channel: channel }))
            }
            0xEE => {
                let channel = data.remove(0);
                Ok(Some(PollEvent::NoteCredit { channel: channel }))
            }
            0xED => Ok(Some(PollEvent::Rejecting)),
            0xEC => Ok(Some(PollEvent::Rejected)),
            0xCC => Ok(Some(PollEvent::Stacking)),
            0xEB => Ok(Some(PollEvent::Stacked)),
            0xEA => Ok(Some(PollEvent::SafeJam)),
            0xE9 => Ok(Some(PollEvent::UnsafeJam)),
            0xE7 => Ok(Some(PollEvent::StackerFull)),
            0xE1 => {
                let channel = data.remove(0);
                Ok(Some(PollEvent::NoteClearedFromFront { channel: channel }))
            }
            0xE2 => {
                let channel = data.remove(0);
                Ok(Some(PollEvent::NoteClearedIntoCashbox { channel: channel }))
            }
            0xB5 => Ok(Some(PollEvent::ChannelDisable)),
            0xAD => Ok(Some(PollEvent::TicketInBezel)),
            0xAF => Ok(Some(PollEvent::PrintedToCashbox)),
            _ => Ok(Some(PollEvent::Unknown(code))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            &PollEvent::SlaveReset => vec![0xF1],
            &PollEvent::Disabled => vec![0xE8],
            &PollEvent::FraudAttempt { ref data } => {
                match data {
                    &FraudAttemptData::BillValidatorData { channel } => vec![0xE6, channel],
                    &FraudAttemptData::SmartHopperData { dispensed: ref coin_values } => {
                        let mut res = vec![0xE6];
                        let mut encoded = CoinValue::encode_list(coin_values);
                        res.append(&mut encoded);
                        res
                    }
                }
            }
            &PollEvent::Initialising => vec![0xB6],
            &PollEvent::Dispensing { dispensed: ref coin_values } => {
                let mut res = vec![0xDA];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::Dispensed { dispensed: ref coin_values } => {
                let mut res = vec![0xD2];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::CoinsLow => vec![0xD3],
            &PollEvent::HopperJammed { dispensed: ref coin_values } => {
                let mut res = vec![0xD5];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::Halted { dispensed: ref coin_values } => {
                let mut res = vec![0xD6];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::Floating { floated: ref coin_values } => {
                let mut res = vec![0xD7];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::Floated { floated: ref coin_values } => {
                let mut res = vec![0xD8];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::Timeout { dispensed: ref coin_values } => {
                let mut res = vec![0xD9];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::IncompletePayout { dispensed: ref coin_values } => {
                let mut res = vec![0xDC];
                let mut encoded = IncompleteCoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::IncompleteFloat { floated: ref coin_values } => {
                let mut res = vec![0xDD];
                let mut encoded = IncompleteCoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::CashboxPaid { dispensed: ref coin_values } => {
                let mut res = vec![0xDE];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::CoinCredit { credit: ref coin_value } => {
                let mut res = vec![0xDF];
                let mut encoded = coin_value.encode();
                res.append(&mut encoded);
                res
            }
            &PollEvent::CoinMechJammed => vec![0xC4],
            &PollEvent::CoinMechReturnActive => vec![0xC5],
            &PollEvent::Emptying => vec![0xC2],
            &PollEvent::Emptied => vec![0xC3],
            &PollEvent::SmartEmptying { dispensed: ref coin_values } => {
                let mut res = vec![0xB3];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::SmartEmptied { dispensed: ref coin_values } => {
                let mut res = vec![0xB4];
                let mut encoded = CoinValue::encode_list(coin_values);
                res.append(&mut encoded);
                res
            }
            &PollEvent::CalibrationFailed { error_code } => vec![0x83, error_code],
            &PollEvent::CoinMechError { error_code } => vec![0xB7, error_code],
            &PollEvent::AttachedCoinMechDisabled => vec![0xBD],
            &PollEvent::AttachedCoinMechEnabled => vec![0xBE],
            &PollEvent::Read { channel } => vec![0xEF, channel],
            &PollEvent::NoteCredit { channel } => vec![0xEE, channel],
            &PollEvent::Rejecting => vec![0xED],
            &PollEvent::Rejected => vec![0xEC],
            &PollEvent::Stacking => vec![0xCC],
            &PollEvent::Stacked => vec![0xEB],
            &PollEvent::SafeJam => vec![0xEA],
            &PollEvent::UnsafeJam => vec![0xE9],
            &PollEvent::StackerFull => vec![0xE7],
            &PollEvent::NoteClearedFromFront { channel } => vec![0xE1, channel],
            &PollEvent::NoteClearedIntoCashbox { channel } => vec![0xE2, channel],
            &PollEvent::ChannelDisable => vec![0xB5],
            &PollEvent::TicketInBezel => vec![0xAD],
            &PollEvent::PrintedToCashbox => vec![0xAF],
            &PollEvent::Unknown(val) => vec![val],
        }
    }
}

#[derive(Debug)]
#[derive(Clone)]
#[allow(dead_code)]
pub enum PayoutError {
    NotEnoughValue,
    CannotPayExactAmount,
    DeviceBusy,
    DeviceDisabled,
    Unknown(u8),
}

impl PayoutError {
    fn from_u8(n: u8) -> PayoutError {
        match n {
            1 => PayoutError::NotEnoughValue,
            2 => PayoutError::CannotPayExactAmount,
            3 => PayoutError::DeviceBusy,
            4 => PayoutError::DeviceDisabled,
            _ => PayoutError::Unknown(n),
        }
    }
}

pub fn calc_crc(data: &Vec<u8>) -> CRC {
    let poly = 0x8005;
    let mut crc = 0xFFFFu16;

    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = ((crc << 1) & 0xffff) ^ poly;
            } else {
                crc <<= 1;
            }
        }
    }
    [(crc & 0xff) as u8, (crc >> 8 & 0xff) as u8]
}

pub fn vec_to_u16(vector: &Vec<u8>) -> Result<u16, ErrorType> {
    let mut rdr = Cursor::new(vector);
    match rdr.read_u16::<LittleEndian>() {
        Ok(data) => Ok(data),
        Err(_) => Err(ErrorType::ParseError),
    }
}

#[allow(dead_code)]
pub fn u16_to_vec(num: u16) -> Vec<u8> {
    let mut data = vec![];
    data.write_u16::<LittleEndian>(num).unwrap();
    data
}

pub fn vec_to_u32(vector: &Vec<u8>) -> Result<u32, ErrorType> {
    let mut rdr = Cursor::new(vector);
    match rdr.read_u32::<LittleEndian>() {
        Ok(data) => Ok(data),
        Err(_) => Err(ErrorType::ParseError),
    }
}

pub fn u32_to_vec(num: u32) -> Vec<u8> {
    let mut data = vec![];
    data.write_u32::<LittleEndian>(num).unwrap();
    data
}

pub fn vec_to_u64(vector: &Vec<u8>) -> Result<u64, ErrorType> {
    let mut rdr = Cursor::new(vector);
    match rdr.read_u64::<LittleEndian>() {
        Ok(data) => Ok(data),
        Err(_) => Err(ErrorType::ParseError),
    }
}

pub fn u64_to_vec(num: u64) -> Vec<u8> {
    let mut data = vec![];
    data.write_u64::<LittleEndian>(num).unwrap();
    data
}


#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Payload {
    pub code: Code,
    pub data: Data,
    pub encrypted: bool,
}


impl Payload {
    pub fn new_u64(code: Code, data_u64: u64, encrypted: bool) -> Payload {
        Payload {
            code: code,
            data: u64_to_vec(data_u64),
            encrypted: encrypted,
        }
    }

    pub fn encode(&self, ecount: ECount, key: Option<Key>) -> Result<Vec<u8>, ErrorType> {
        let mut temp = Vec::<u8>::new();
        let code_byte = match &self.code {
            &Code::CommandCode(ref cmd) => cmd.to_u8(),
            &Code::ResponseCode(ref resp) => resp.to_u8(),
        };
        temp.push(code_byte);
        temp.append(&mut self.data.clone());

        match self.encrypted {
            true => {
                if let None = key {
                    Err(ErrorType::KeyNotSet)
                } else {
                    Payload::encrypt(&temp, ecount, key.unwrap())
                }
            }
            false => Ok(temp),
        }
    }

    pub fn decode(raw: &Vec<u8>, ecount: ECount, key: Option<Key>) -> Result<Payload, ErrorType> {
        let encrypted = raw[0] == STEX;
        let mut data = match encrypted {
            true => {
                if let None = key {
                    return Err(ErrorType::KeyNotSet);
                } else {
                    Payload::decrypt(raw, ecount, key.unwrap())?
                }
            }
            false => raw.clone(),
        };
        let code_byte = data.remove(0);

        // decode always assumes that it's decoding a response, so it will interpret the first byte as response code
        Ok(Payload {
               code: Code::ResponseCode(Response::from_u8(code_byte)),
               data: data,
               encrypted: encrypted,
           })
    }

    fn encrypt(raw_payload: &Vec<u8>, ecount: ECount, key: Key) -> Result<Vec<u8>, ErrorType> {
        let mut to_encode = Vec::<u8>::new();
        to_encode.push(raw_payload.len() as u8);

        let mut ecount_vec = u32_to_vec(ecount);
        to_encode.append(&mut ecount_vec);

        to_encode.extend_from_slice(raw_payload);
        // add packing to make length mod 16
        let packing_len = 16 - ((to_encode.len() + 2) % 16);
        to_encode.extend(iter::repeat(0u8).take(packing_len));

        // CRC of the encrypted part
        let ecrc = calc_crc(&to_encode);
        to_encode.extend_from_slice(&ecrc);

        let enc_len = to_encode.len();

        let aes_enc = aessafe::AesSafe128Encryptor::new(&key[..]);
        let mut encryptor = blockmodes::EcbEncryptor::new(aes_enc, blockmodes::NoPadding);

        let mut out = Vec::<u8>::with_capacity(enc_len);
        out.resize(enc_len, 0u8);

        {
            let mut buff_in = RefReadBuffer::new(&to_encode);
            let mut buff_out = RefWriteBuffer::new(&mut out);

            match encryptor.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferResult::BufferUnderflow) => {}
                Ok(BufferResult::BufferOverflow) => {
                    panic!("ESSP Encryption buffer overflow"); // this should not happend with ECB encryption mode
                }
                Err(err) => return Err(ErrorType::CryptoError(err)),
            }
        }
        // debug!("Ciphertext: {:?}", out);

        // put STEX in after encryption
        out.insert(0, STEX);

        Ok(out)
    }

    fn decrypt(raw: &Vec<u8>, ecount: ECount, key: Key) -> Result<Vec<u8>, ErrorType> {
        let mut to_decode = raw.clone();

        // removeing STEX
        to_decode.remove(0);

        // debug!("To decode: {:?}", &to_decode);
        let dec_len = to_decode.len();

        let aes_dec = aessafe::AesSafe128Decryptor::new(&key[..]);
        let mut decryptor = blockmodes::EcbDecryptor::new(aes_dec, blockmodes::NoPadding);

        let mut out = Vec::<u8>::with_capacity(dec_len);
        out.resize(dec_len, 0u8);

        {
            let mut buff_in = RefReadBuffer::new(&to_decode);
            let mut buff_out = RefWriteBuffer::new(&mut out);

            match decryptor.decrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferResult::BufferUnderflow) => {}
                Ok(BufferResult::BufferOverflow) => {
                    panic!("ESSP Decryption buffer overflow!"); // This should not happend with ECB encryption
                }
                Err(err) => return Err(ErrorType::CryptoError(err)),
            }
        }
        // debug!("Decoded: {:?}", out);

        let crc_2 = out.pop().unwrap();
        let crc_1 = out.pop().unwrap();

        let received_crc: CRC = [crc_1, crc_2];
        let expected_crc = calc_crc(&out);
        if received_crc != expected_crc {
            return Err(ErrorType::EncryptedCRCError);
        }

        let payload_len = out.remove(0);
        // TODO check len
        // debug!("payload len: {:?}", payload_len);

        // cut the counter
        let mut payload = out.split_off(4);
        let received_ecount = vec_to_u32(&out)?;

        // check ecount
        if received_ecount != ecount {
            return Err(ErrorType::EncryptionCounterError);
        }

        // cut the packing and crc
        let _ = payload.split_off(payload_len as usize);

        // debug!("payload after decryption: {:?}", payload);

        Ok(payload)
    }

    pub fn parse_as_u64(&self) -> Result<u64, ErrorType> {
        vec_to_u64(&self.data)
    }

    pub fn parse_as_u32(&self) -> Result<u32, ErrorType> {
        vec_to_u32(&self.data)
    }

    pub fn parse_as_payout_error(&self) -> PayoutError {
        PayoutError::from_u8(self.data[0])
    }

    pub fn parse_as_poll_response(&self, device_type: &DeviceType) -> Result<Vec<PollEvent>, ErrorType> {
        let mut event_data = self.data.clone();
        let mut events = Vec::<PollEvent>::new();
        while event_data.len() > 0 {
            let event = PollEvent::parse_first(&mut event_data, &device_type)?;
            if let Some(event) = event {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn parse_as_coin_values(&self) -> Result<Vec<CoinNumValue>, ErrorType> {
        CoinNumValue::decode_list(&mut self.data.clone())
    }

    pub fn parse_as_cashbox_payout_data(&self) -> Result<CashboxPayoutData, ErrorType> {
        CashboxPayoutData::decode(&mut self.data.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Message {
    pub slave_id: SlaveID,
    pub payload: Payload,
}

impl Message {
    // should be called after CRC is calculated
    fn byte_stuff(data: &Data) -> Data {
        // if data has STX, insert another STX
        let mut temp = Vec::<u8>::new();
        temp.push(data[0]);

        // we ignore the first byte, it should not be stuffed
        for byte in data[1..].iter() {
            if *byte == STX {
                temp.push(STX);
            }
            temp.push(*byte);
        }

        temp
    }

    fn byte_destuff(data: &DataSlice) -> Data {
        let mut res = vec![];

        let mut previous_byte = 0u8;
        for i in 0..data.len() {
            if previous_byte == STX && data[i] == STX {
                previous_byte = 0u8;
            } else {
                previous_byte = data[i];
                res.push(previous_byte);
            }
        }

        res
    }

    pub fn encode(&self, seq: bool, ecount: ECount, key: Option<Key>) -> Result<Vec<u8>, ErrorType> {
        let mut temp = Vec::<u8>::new();
        if seq {
            temp.push(self.slave_id + 128u8);
        } else {
            temp.push(self.slave_id);
        }

        let mut encoded_payload = self.payload.encode(ecount, key)?;
        temp.push(encoded_payload.len() as u8);
        temp.append(&mut encoded_payload);

        // CRC is calculated with every byte except STX
        let crc = calc_crc(&temp);
        temp.extend_from_slice(&crc);

        // put STX at the beginning
        temp.insert(0, STX);

        // returning the byte stuffed version of the message
        Ok(Message::byte_stuff(&temp))
    }

    pub fn decode(buffer: &mut Vec<u8>, seq: bool, ecount: ECount, key: Option<Key>) -> Result<Message, ErrorType> {
        if buffer.len() < 3 {
            return Err(ErrorType::PartialMessage);
        }

        while buffer[0] != STX || buffer[1] == STX {
            warn!("Message alignment error, clearing buffer until next STX! Bad buffer: {:?}", buffer);

            let mut invalid_message: Vec<u8> = vec![];
            invalid_message.push(buffer.remove(0));

            let stx_pos = buffer.iter().position(|&r| r == STX);
            match stx_pos {
                Some(pos) => {
                    invalid_message.extend(buffer.drain(0..pos as usize));
                    warn!("Clearing {} bytes from buffer: {:?}, remaining buffer: {:?}", pos + 1, invalid_message, buffer);
                }
                None => {
                    invalid_message.append(buffer);
                    buffer.clear();
                    warn!("Clearing from buffer: {:?}, buffer is empty", invalid_message);
                }
            }

            if buffer.len() < 3 {
                return Err(ErrorType::PartialMessage);
            }
        }

        trace!("Result buffer: {:?}", buffer);

        let buffer_size: usize = buffer.len();
        if buffer_size < 3 {
            return Err(ErrorType::PartialMessage);
        }

        let mut slave_id = buffer[1];
        let received_seq;
        if slave_id >= 128 {
            received_seq = true;
            slave_id -= 128;
        } else {
            received_seq = false;
        }

        if slave_id > MAX_SLAVE_ID {
            debug!("Invalid slave ID received: {:?}", slave_id);
            buffer.drain(0..2);
            return Err(ErrorType::SlaveIdError);
        }

        trace!("Decoding buffer: {:?}", buffer);

        let payload_size = buffer[2] as usize;
        let expected_msg_size = payload_size + 5;

        let mut to_read: usize = 0;
        let mut destuffed: Vec<u8> = vec![];
        let mut destuffed_size = 0;

        trace!("Guessing message size: {}", expected_msg_size);

        while destuffed_size != expected_msg_size {
            to_read = to_read + expected_msg_size - destuffed_size;

            if buffer_size < to_read {
                trace!("Partial message: {:?} - size: {}, expected: {}", buffer, buffer_size, to_read);
                return Err(ErrorType::PartialMessage);
            };

            trace!("Message to destuff: {:?}", &buffer[0..to_read]);

            destuffed = Message::byte_destuff(&buffer[0..to_read]);
            destuffed_size = destuffed.len();

            let removed = to_read - destuffed_size;
            trace!("Byte stuffing removed, got: {:?} - diff: {}", destuffed, removed);
        }

        // if success, really drain the message
        buffer.drain(0..to_read);
        // don't touch buffer after this, it may have the next message

        if received_seq == seq {
            // Why is this not working omg???
            //debug!("SEQ error in ESSP message: {:?}", raw_msg);
            //return Err(ErrorType::NotAResponse);
        }

        if !Message::validate_crc(&destuffed) {
            error!("CRC error on ESSP message: {:?}", destuffed);
            return Err(ErrorType::CRCError);
        }

        trace!("Received valid ESSP message for slaveID: {:?}, seq {:?} - raw message {:?}", slave_id, received_seq, destuffed);

        // cut the payload part
        let raw_payload = destuffed.drain(3..(payload_size + 3)).collect();

        let decoded_payload = Payload::decode(&raw_payload, ecount, key)?;

        trace!("Decoded: {:?}", decoded_payload);

        Ok(Message {
               slave_id: slave_id,
               payload: decoded_payload,
           })
    }

    pub fn validate_crc(raw: &Vec<u8>) -> bool {
        if raw.is_empty() {
            error!("Validate CRC called on empty ESSP message!");
            return false;
        }

        let mut data = raw.clone();
        // remove STX
        data.remove(0);

        let crc2 = data.pop().unwrap();
        let crc1 = data.pop().unwrap();

        [crc1, crc2] == calc_crc(&data)
    }
}

fn mod_pow(num: u64, pow: u64, modulo: u64) -> u64 {
    let mut num = num;
    let mut pow = pow;
    let mut ret = 1;
    while pow > 0 {
        if pow & 1 == 1 {
            ret = (ret * num) % modulo;
        }
        pow >>= 1;
        num = (num * num) % modulo;
    }
    ret
}

pub fn calc_inter_key(generator: Generator, modulus: Modulus) -> (InterKey, InterKey) {
    let mut os_rng = OsRng::new().unwrap();
    let host_rnd = os_rng.next_u64();

    let inter_key: InterKey = mod_pow(generator, host_rnd, modulus);

    (inter_key, host_rnd)
}

pub fn calc_key(slave_inter_key: InterKey, host_rnd: InterKey, modulus: Modulus, fix_key: InterKey) -> [u8; 16] {
    let negotiated_key = mod_pow(slave_inter_key, host_rnd, modulus);
    let mut negotiated_key_vec = u64_to_vec(negotiated_key);
    let mut fix_key_vec = u64_to_vec(fix_key);
    let mut key_calc = vec![];

    // negotiated is first?
    key_calc.append(&mut fix_key_vec);
    key_calc.append(&mut negotiated_key_vec);

    let mut array = [0u8; 16];
    for (&x, p) in key_calc.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn essp_crc() {
        let data = vec![128, 1, 240];
        assert_eq!(calc_crc(&data), [35, 128]);
    }

    #[test]
    fn essp_destuff_payload() {
        let buffer_original = vec![127, 16, 17, 126, 3, 4, 138, 40, 34, 127, 127, 49, 153, 193, 182, 35, 94, 11, 49, 201, 112];
        let buffer_expected = vec![127, 16, 17, 126, 3, 4, 138, 40, 34, 127, 49, 153, 193, 182, 35, 94, 11, 49, 201, 112];
        let res = Message::byte_destuff(&buffer_original);
        assert_eq!(res, buffer_expected);
    }

    #[test]
    fn essp_destuff_crc1() {
        let buffer_original = vec![127, 16, 17, 126, 202, 137, 148, 122, 207, 20, 164, 91, 71, 249, 182, 87, 229, 42, 127, 127, 220];
        let buffer_expected = vec![127, 16, 17, 126, 202, 137, 148, 122, 207, 20, 164, 91, 71, 249, 182, 87, 229, 42, 127, 220];
        let res = Message::byte_destuff(&buffer_original);
        assert_eq!(res, buffer_expected);
    }

    #[test]
    fn essp_destuff_crc2() {
        let buffer_original = vec![127, 168, 17, 126, 147, 14, 209, 35, 122, 97, 150, 16, 194, 114, 247, 10, 162, 95, 197, 47, 131, 127, 127];
        let buffer_expected = vec![127, 168, 17, 126, 147, 14, 209, 35, 122, 97, 150, 16, 194, 114, 247, 10, 162, 95, 197, 47, 131, 127];
        let res = Message::byte_destuff(&buffer_original);
        assert_eq!(res, buffer_expected);
    }

    #[test]
    fn essp_double_destuff() {
        let buffer_original = vec![127, 16, 18, 126, 3, 4, 138, 40, 34, 127, 127, 127, 127, 49, 153, 193, 182, 35, 94, 11, 49, 201, 112];
        let buffer_expected = vec![127, 16, 18, 126, 3, 4, 138, 40, 34, 127, 127, 49, 153, 193, 182, 35, 94, 11, 49, 201, 112];
        let res = Message::byte_destuff(&buffer_original);
        assert_eq!(res, buffer_expected);
    }

    #[test]
    fn essp_decode_partial() {
        let mut buffer = vec![127, 168, 2, 240, 127, 127, 49, 129, 127, 16, 17, 126, 3, 4, 138, 40, 34, 127, 127, 49, 153, 193, 182, 35, 94, 11, 49];

        let res = Message::decode(&mut buffer, false, 0, None);
        let expected = Message {
            slave_id: 40,
            payload: Payload {
                code: Code::ResponseCode(Response::Ok),
                data: vec![127],
                encrypted: false,
            },
        };
        assert_eq!(res.unwrap(), expected);

        let res = Message::decode(&mut buffer, false, 0, None);
        assert!(res.is_err());
        match res.unwrap_err() {
            ErrorType::PartialMessage => {}
            other => panic!("Expected PartialMessage, got: {:?}", other),
        }
        assert_eq!(buffer.len(), 19);
    }

    #[test]
    fn essp_decode_double_stuffed() {
        let mut buffer = vec![127, 168, 2, 240, 127, 127, 49, 129, 127, 168, 5, 240, 100, 127, 127, 127, 127, 200, 174, 30];

        // decode first
        let mut res = Message::decode(&mut buffer, false, 0, None);
        let expected1 = Message {
            slave_id: 40,
            payload: Payload {
                code: Code::ResponseCode(Response::Ok),
                data: vec![127],
                encrypted: false,
            },
        };
        assert_eq!(res.unwrap(), expected1);

        // decode second, should not be byte de-stuffed twice!
        res = Message::decode(&mut buffer, false, 0, None);
        let expected2 = Message {
            slave_id: 40,
            payload: Payload {
                code: Code::ResponseCode(Response::Ok),
                data: vec![100, 127, 127, 200],
                encrypted: false,
            },
        };
        assert_eq!(res.unwrap(), expected2);
        assert!(buffer.is_empty());
    }

    /*#[test]
    fn essp_decode_encrypted() {
        // TODO
    }*/

    #[test]
    fn essp_decode_unencrypted() {
        let mut buffer = vec![127, 168, 9, 240, 199, 63, 16, 0, 0, 0, 0, 0, 254, 238];
        let res = Message::decode(&mut buffer, false, 0, None);
        assert!(res.is_ok());
        let expected = Message {
            slave_id: 40,
            payload: Payload {
                code: Code::ResponseCode(Response::Ok),
                data: vec![199, 63, 16, 0, 0, 0, 0, 0],
                encrypted: false,
            },
        };
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());
    }

    #[test]
    fn essp_message_alignment_self_heal() {
        let expected = Message {
            slave_id: 0,
            payload: Payload {
                code: Code::ResponseCode(Response::Ok),
                data: vec![],
                encrypted: false,
            },
        };

        let mut buffer = vec![9, 240, 199, 127, 127, 127, 127, 127, 128, 1, 240, 35, 128];
        let mut res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());

        buffer = vec![199, 127, 127, 127, 127, 127, 128, 1, 240, 35, 128];
        res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());

        let mut buffer = vec![127, 127, 127, 127, 127, 128, 1, 240, 35, 128];
        let res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());

        let mut buffer = vec![127, 127, 127, 127, 128, 1, 240, 35, 128];
        let res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());

        let mut buffer = vec![127, 127, 127, 128, 1, 240, 35, 128];
        let res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());

        let mut buffer = vec![127, 128, 1, 240, 35, 128];
        let res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());

        let mut buffer = vec![127, 128, 1, 240, 35, 128];
        let res = Message::decode(&mut buffer, false, 0, None);
        assert_eq!(res.unwrap(), expected);
        assert!(buffer.is_empty());
    }

}
