use serial::prelude::*;
use std;
use std::io::{Write, Read};
use std::io::ErrorKind::TimedOut;
use std::error::Error;
use std::time::Duration;
use std::convert;

use protocol::*;

#[derive(Debug)]
pub enum ClientError {
    ESSPError(ErrorType),
    SerialError(serial::Error),
    IOError(std::io::Error),
}

impl convert::From<serial::Error> for ClientError {
    fn from(e: serial::Error) -> ClientError {
        ClientError::SerialError(e)
    }
}

impl convert::From<ErrorType> for ClientError {
    fn from(e: ErrorType) -> ClientError {
        ClientError::ESSPError(e)
    }
}

impl convert::From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> ClientError {
        ClientError::IOError(e)
    }
}

impl Clone for ClientError {
    fn clone(&self) -> Self {
        match self {
            &ClientError::ESSPError(ref e) => ClientError::ESSPError(e.clone()),
            &ClientError::IOError(ref e) => ClientError::IOError(std::io::Error::new(e.kind(), e.description())),
            &ClientError::SerialError(ref e) => ClientError::SerialError(serial::Error::new(e.kind(), e.description())),
        }
    }
}

pub trait ESSPClient {
    fn read(&mut self, seq: bool, ecount: ECount, key: Option<Key>) -> Result<Vec<Message>, ClientError>;
    fn clear_buffer(&mut self);
    fn send(&mut self, msg: &Message, seq: bool, ecount: ECount, key: Option<Key>) -> Result<(), ClientError>;
    fn set_poll_events(&mut self, poll_events: Vec<PollEvent>);
}

pub struct SerialClient {
    port: serial::SystemPort,
    buffer: Vec<u8>,
}

#[allow(dead_code)]
impl SerialClient {
    pub fn new(port_name: &String, serial_settings: &serial::PortSettings) -> Result<SerialClient, ClientError> {
        // debug!("Connecting to ESSP on port: {:?}", port_name);

        let mut port_temp = serial::open(&port_name)?;
        port_temp.configure(&serial_settings)?;

        port_temp.set_timeout(Duration::from_millis(100))?;

        Ok(SerialClient {
               port: port_temp,
               buffer: Vec::<u8>::new(),
           })
    }

    fn read_and_decode(&mut self, received: &mut Vec<u8>, messages: &mut Vec<Message>, seq: bool, ecount: ECount, key: Option<Key>) {
        // debug!("Received: {:?}", received);
        self.buffer.append(received);
        // debug!("Buffer: {:?}", self.buffer);

        // decode will leave the remaining stuff in the buffer
        let decode_res = Message::decode(&mut self.buffer, seq, ecount, key);
        match decode_res {
            Ok(message) => {
                messages.push(message);
            }
            Err(ErrorType::PartialMessage) => {
                trace!("Partial message: {:?}", self.buffer);
            }
            Err(ErrorType::NotAResponse) => {
                debug!("Not a response, ignoring");
            }
            Err(e) => debug!("*********Unexpected error while decoding, dropping message: {:?}", e),
        }
    }

    fn read_from_serial(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: [u8; 260] = [0; 260];
        let mut rec: Vec<u8> = Vec::<u8>::new();

        let read_res = self.port.read(&mut buf);
        // debug!("read_res: {:?}", read_res);

        match read_res {
            Ok(usize) => {
                rec.extend_from_slice(&buf[..usize]);
                Ok(rec)
            }
            Err(ref e) if e.kind() == TimedOut => {
                // debug!("Timeout");
                // continue, this is not really an error
                Ok(rec)
            }
            Err(e) => return Err(e),
        }
    }
}


impl ESSPClient for SerialClient {
    fn send(&mut self, msg: &Message, seq: bool, ecount: ECount, key: Option<Key>) -> Result<(), ClientError> {
        let buf: Vec<u8> = msg.encode(seq, ecount, key)?;
        // debug!("Sending ESSP message: {:?}", msg);
        // debug!("Sending ESSP message encoded&encrypted: {:?}", buf);

        self.port.write_all(&buf[..])?;

        Ok(())
    }


    fn read(&mut self, seq: bool, ecount: ECount, key: Option<Key>) -> Result<Vec<Message>, ClientError> {

        let mut messages = Vec::<Message>::new();

        let mut counter = 0;

        while (messages.len() < 1) && (counter < 40) {
            let mut received = self.read_from_serial()?;
            // debug!("Received on serial: {:?}", received);
            if received.len() != 0 {
                self.read_and_decode(&mut received, &mut messages, seq, ecount, key);
            }
            counter += 1;
        }

        Ok(messages)
    }

    fn clear_buffer(&mut self) {
        if self.buffer.len() != 0 {
            warn!("ESSP timeout in the middle of a message! Clearing partial message from buffer: {:?}", self.buffer);
            self.buffer.clear();
        }
    }

    fn set_poll_events(&mut self, _: Vec<PollEvent>) {}
}


pub struct DummyClient {
    last_message: Option<Message>,
    poll_events: Vec<PollEvent>,
    changed: bool,
}

impl DummyClient {
    pub fn new() -> DummyClient {
        warn!("Creating MOCK ESSP Client");
        DummyClient {
            last_message: None,
            poll_events: vec![],
            changed: false,
        }
    }
}

impl ESSPClient for DummyClient {
    fn send(&mut self, msg: &Message, _: bool, _: ECount, _: Option<Key>) -> Result<(), ClientError> {
        self.last_message = Some(msg.clone());
        Ok(())
    }

    fn read(&mut self, _: bool, _: ECount, _: Option<Key>) -> Result<Vec<Message>, ClientError> {
        let msg = self.last_message.clone();
        match msg {
            Some(message) => {
                match message.payload.code {
                    Code::CommandCode(code) => {
                        match code {
                            Command::RequestKeyExchange => {
                                Ok(vec![Message {
                                            slave_id: 1,
                                            payload: Payload {
                                                code: Code::ResponseCode(Response::Ok),
                                                data: vec![3, 0, 0, 0, 0, 0, 0, 0],
                                                encrypted: false,
                                            },
                                        }])
                            }
                            Command::GetAllLevels => {
                                Ok(vec![Message {
                                            slave_id: 1,
                                            payload: Payload {
                                                code: Code::ResponseCode(Response::Ok),
                                                data: vec![0],
                                                encrypted: false,
                                            },
                                        }])
                            }
                            Command::GetMinimumPayout => {
                                Ok(vec![Message {
                                            slave_id: 1,
                                            payload: Payload {
                                                code: Code::ResponseCode(Response::Ok),
                                                data: vec![0x50u8, 0xC3u8, 0u8, 0u8],
                                                encrypted: false,
                                            },
                                        }])
                            }
                            Command::Poll => {
                                let size = self.poll_events.len();
                                if size == 0 {
                                    Ok(vec![Message {
                                                slave_id: 1,
                                                payload: Payload {
                                                    code: Code::ResponseCode(Response::Ok),
                                                    data: vec![],
                                                    encrypted: false,
                                                },
                                            }])
                                } else {
                                    let mut encoded = vec![];
                                    for elem in self.poll_events.iter() {
                                        let mut elem_enc: Vec<u8> = elem.encode();
                                        encoded.append(&mut elem_enc);
                                    }
                                    self.poll_events = vec![];
                                    self.changed = false;
                                    Ok(vec![Message {
                                                slave_id: 1,
                                                payload: Payload {
                                                    code: Code::ResponseCode(Response::Ok),
                                                    data: encoded,
                                                    encrypted: false,
                                                },
                                            }])
                                }
                            }
                            _ => {
                                Ok(vec![Message {
                                            slave_id: 1,
                                            payload: Payload {
                                                code: Code::ResponseCode(Response::Ok),
                                                data: vec![],
                                                encrypted: false,
                                            },
                                        }])
                            }
                        }
                    }
                    Code::ResponseCode(_) => panic!("Sent message had a response code instead of a command code!"),
                }
            }
            None => panic!("Reading on dummy client before sending anything"),
        }
    }

    fn clear_buffer(&mut self) {}

    fn set_poll_events(&mut self, poll_events: Vec<PollEvent>) {
        self.poll_events.append(&mut poll_events.clone());
        self.changed = true;
    }
}
