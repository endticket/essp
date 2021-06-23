use protocol::*;
use client::*;
use itertools::Itertools;

pub struct ESSPDevice {
    pub client: Box<ESSPClient + 'static>,
    pub address: SlaveID,
    seq: bool,
    ecount: ECount, // TODO check it against the received counter when decrypting messages
    generator: Generator,
    modulus: Modulus,
    host_rnd: InterKey,
    host_inter_key: InterKey,
    key: Option<Key>,
    enc_key_fixed: InterKey,
    pub currency: String,
    pub scaling_factor: u32,
}

#[allow(dead_code)]
impl ESSPDevice {
    pub fn new(port_name: &String,
               serial_settings: &serial::PortSettings,
               address: SlaveID,
               enc_key_fixed: InterKey,
               currency: &str,
               scaling_factor: u32,
               mock: bool)
               -> Result<ESSPDevice, ClientError> {
        // TODO get primes from the file
        // let generator = 0xFFFFFFFFFFFFFFC5u64; // largest 64bit prime: 18446744073709551557
        let generator = 0x000000003A8F05C5u64; // example from documentation: 982451653
        let modulus = 0x000000000013A68Du64; // example from documentation: 1287821

        let (inter_key, host_rnd) = calc_inter_key(generator, modulus);

        match mock {
            false => {
                let temp_client = SerialClient::new(port_name, &serial_settings)?;

                Ok(ESSPDevice {
                       client: Box::new(temp_client),
                       address: address,
                       seq: false,
                       ecount: 0,
                       generator: generator,
                       modulus: modulus,
                       host_rnd: host_rnd,
                       host_inter_key: inter_key,
                       key: None,
                       enc_key_fixed: enc_key_fixed,
                       currency: currency.to_owned(),
                       scaling_factor: scaling_factor,
                   })
            }
            true => {
                let dummy_client = DummyClient::new();
                Ok(ESSPDevice {
                       client: Box::new(dummy_client),
                       address: address,
                       seq: false,
                       ecount: 0,
                       generator: generator,
                       modulus: modulus,
                       host_rnd: host_rnd,
                       host_inter_key: inter_key,
                       key: None,
                       enc_key_fixed: enc_key_fixed,
                       currency: currency.to_owned(),
                       scaling_factor: scaling_factor,
                   })
            }
        }
    }

    pub fn set_poll_events(&mut self, poll_events: Vec<PollEvent>) {
        self.client.set_poll_events(poll_events);
    }

    pub fn send_and_check_reply(&mut self, msg: &Message) -> Result<Payload, ClientError> {
        let sent_with_seq = self.send(msg)?;

        // debug!("Waiting for Reply");
        let received = self.client.read(sent_with_seq, self.ecount, self.key)?;
        if received.len() > 0 {
            let ref reply = received[0];
            match reply.payload.code {
                Code::ResponseCode(Response::Unknown(_)) => {
                    error!("Reply received with unknown reply code: {:?} for request: {:?}", reply.payload, msg);
                    Err(ClientError::ESSPError(ErrorType::UnknownResponse))
                }
                Code::ResponseCode(Response::Ok) => {
                    // debug!("OK Reply received: {:?}", reply.payload);
                    Ok(reply.payload.clone())
                }
                _ => {
                    debug!("Not OK reply code: {:?} for request: {:?}", reply.payload, msg);
                    Err(ClientError::ESSPError(ErrorType::NotOkResponse(reply.payload.clone())))
                }
            }
        } else {
            self.client.clear_buffer();
            Err(ClientError::ESSPError(ErrorType::NoResponse))
        }
    }


    pub fn send(&mut self, msg: &Message) -> Result<bool, ClientError> {
        // TODO send the message, then wait 1 second for the reply
        // if no reply, re-transmit
        // after 20 retries, sending failed
        let send_with_seq = self.seq;
        self.client.send(msg, send_with_seq, self.ecount, self.key)?;
        self.seq = !self.seq;
        if msg.payload.encrypted {
            self.ecount = self.ecount.wrapping_add(1);
        }
        Ok(send_with_seq)
    }


    pub fn create_message(&mut self, payload: Payload) -> Message {
        Message {
            slave_id: self.address,
            payload: payload,
        }
    }

    // *********************************
    //  ESSP commands for Smart Hoppers
    // *********************************

    pub fn sync(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::Sync),
                                              data: vec![],
                                              encrypted: false,
                                          });

        // this should be explicitly set to false, but it's not working somehow, so we now just try it twice...
        // self.seq = false;
        self.send_and_check_reply(&message)
    }

    pub fn reset(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::Reset),
                                              data: vec![],
                                              encrypted: false,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn host_protocol_version(&mut self, version: u8) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::HostProtocolVersion),
                                              data: vec![version],
                                              encrypted: false,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn poll(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::Poll),
                                              data: vec![],
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn get_serial_number(&mut self, encrypted: bool) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::GetSerialNumber),
                                              data: vec![],
                                              encrypted: encrypted,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn disable(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::Disable),
                                              data: vec![],
                                              encrypted: false,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn enable(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::Enable),
                                              data: vec![],
                                              encrypted: false,
                                          });
        self.send_and_check_reply(&message)
    }

    // pub fn get_firmware_version(&mut self) -> Result<Payload, ClientError> {}

    // pub fn get_dataset_version(&mut self) -> Result<Payload, ClientError> {}

    // pub fn get_firmware_version(&mut self) -> Result<Payload, ClientError> {}

    // pub fn setup_request(&mut self) -> Result<Payload, ClientError> {}

    // pub fn poll_with_ack(&mut self) -> Result<Payload, ClientError> {}

    pub fn event_ack(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::EventAck),
                                              data: vec![],
                                              encrypted: false,
                                          });
        self.send_and_check_reply(&message)
    }

    // pub fn set_denomination_route(&mut self) -> Result<Payload, ClientError> {}

    // pub fn get_denomination_route(&mut self) -> Result<Payload, ClientError> {}

    pub fn payout_amount(&mut self, amount: u32, country_code: &str, test: bool) -> Result<Payload, ClientError> {
        let mut vec = vec![];
        let mut amount_vec = u32_to_vec(amount);
        vec.append(&mut amount_vec);
        vec.extend_from_slice(country_code.as_bytes());
        vec.push(match test {
                     true => 0x19u8,
                     false => 0x58u8,
                 });

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::PayoutAmount),
                                              data: vec,
                                              encrypted: true,
                                          });
        let reply = self.send_and_check_reply(&message);
        if let &Err(ClientError::ESSPError(ErrorType::NotOkResponse(ref payload))) = &reply {
            match payload.code {
                Code::ResponseCode(Response::CommandCannotBeProcessed) => {
                    warn!("Payout error: {:?}", payload.parse_as_payout_error());
                }
                _ => error!("Unexpected response code received for payout amount command"),
            }
        }
        reply
    }

    // pub fn get_denomination_level(&mut self) -> Result<Payload, ClientError> {}

    pub fn set_denomination_level(&mut self, coin_data: CoinNumValue) -> Result<Payload, ClientError> {
        // coins to add - 0 will clear it

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SetDenominationLevel),
                                              data: coin_data.encode(),
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    // pub fn halt_payout(&mut self) -> Result<Payload, ClientError> {}

    // this should not be used, because we use set_cashbox_payout_limit which is by denomination, so don't float based on sum value
    pub fn float_amount(&mut self, minimum_payout: u16, payout_value: u32, country_code: String, test: bool) -> Result<Payload, ClientError> {
        let mut vec = vec![];
        let mut minimum_vec = u16_to_vec(minimum_payout);
        vec.append(&mut minimum_vec);
        let mut payout_vec = u32_to_vec(payout_value);
        vec.append(&mut payout_vec);
        vec.extend_from_slice(country_code.as_bytes());
        vec.push(match test {
                     true => 0x19u8,
                     false => 0x58u8,
                 });

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::FloatAmount),
                                              data: vec,
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn get_min_payout(&mut self) -> Result<u32, ClientError> {
        let data = self.currency.as_bytes().to_vec();

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::GetMinimumPayout),
                                              data: data,
                                              encrypted: false,
                                          });

        match self.send_and_check_reply(&message) {
            Ok(reply) => {
                match reply.parse_as_u32() {
                    Ok(data) => Ok(data / self.scaling_factor),
                    Err(e) => Err(ClientError::ESSPError(e)),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn set_coin_mech_inhibit(&mut self, enabled: bool, coin_value: u16) -> Result<Payload, ClientError> {
        let mut data = match enabled {
            true => vec![1u8],
            false => vec![0u8],
        };
        let value_scaled: u16 = coin_value as u16 * self.scaling_factor as u16;
        let mut val = u16_to_vec(value_scaled);
        data.append(&mut val);
        data.extend_from_slice(self.currency.as_bytes());

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SetCoinMechInhibits),
                                              data: data,
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    // pub fn payout_by_denomination(&mut self) -> Result<Payload, ClientError> {}

    pub fn float_by_denomination(&mut self, denom_vec: Vec<CoinNumValue>, test: bool) -> Result<Payload, ClientError> {
        // manual float
        let mut data = vec![denom_vec.len() as u8];

        for denom_data in denom_vec {
            let mut denom_enc = denom_data.encode();
            data.append(&mut denom_enc);
        }

        data.push(match test {
                      true => 0x19u8,
                      false => 0x58u8,
                  });

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::FloatByDenomination),
                                              data: data,
                                              encrypted: true,
                                          });

        self.send_and_check_reply(&message)
    }

    // send everything to cashbox, don't know how much
    pub fn empty_all(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::EmptyAll),
                                              data: vec![],
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn set_options(&mut self, reg0: u8, reg1: u8) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SetHopperOptions),
                                              data: vec![reg0, reg1],
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn get_options(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::GetHopperOptions),
                                              data: vec![],
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    pub fn coin_mech_global_inhibit(&mut self, enabled: bool) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SetCoinMechGlobalInhibit),
                                              data: match enabled {
                                                  true => vec![1u8],
                                                  false => vec![0u8],
                                              },
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    // send everything to cashbox, records the sum value of emptied stuff, detailed values can be retrieved with cashbox_payout_operation_data
    pub fn smart_empty(&mut self) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SmartEmpty),
                                              data: vec![],
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }

    // can be sent after payout / float / smart empty to get the amount detailed by denomination + num of unknowns
    pub fn cashbox_payout_operation_data(&mut self) -> Result<CashboxPayoutData, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::CashboxPayoutOperationData),
                                              data: vec![],
                                              encrypted: true,
                                          });
        match self.send_and_check_reply(&message) {
            Ok(reply) => {
                match reply.parse_as_cashbox_payout_data() {
                    Ok(data) => Ok(data),
                    Err(e) => Err(ClientError::ESSPError(e)),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_all_levels(&mut self) -> Result<Vec<CoinNumValue>, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::GetAllLevels),
                                              data: vec![],
                                              encrypted: true,
                                          });
        match self.send_and_check_reply(&message) {
            Ok(reply) => {
                match reply.parse_as_coin_values() {
                    Ok(data) => Ok(data),
                    Err(e) => Err(ClientError::ESSPError(e)),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn set_generator(&mut self) -> Result<Payload, ClientError> {
        let payload = Payload::new_u64(Code::CommandCode(Command::SetGenerator), self.generator, false);
        let message = self.create_message(payload);
        self.send_and_check_reply(&message)
    }

    pub fn set_modulus(&mut self) -> Result<Payload, ClientError> {
        let payload = Payload::new_u64(Code::CommandCode(Command::SetModulus), self.modulus, false);
        let message = self.create_message(payload);
        self.send_and_check_reply(&message)
    }

    pub fn request_key_exchange(&mut self) -> Result<Payload, ClientError> {
        let payload = Payload::new_u64(Code::CommandCode(Command::RequestKeyExchange), self.host_inter_key.clone(), false);
        let message = self.create_message(payload);
        let reply = self.send_and_check_reply(&message);
        if let &Ok(ref payload) = &reply {
            match payload.code {
                Code::ResponseCode(Response::Ok) => {
                    // debug!("slave_inter_key: {:?}", payload.data);
                    // debug!("slave_inter_key as u64: {:?}", payload.parse_as_u64());

                    let slave_inter_key = payload.parse_as_u64()?;
                    self.key = Some(calc_key(slave_inter_key, self.host_rnd, self.modulus, self.enc_key_fixed));
                    self.ecount = 0;
                    debug!("Resetting encryption counter and setting new key: {:?}", self.key);
                }
                _ => {
                    error!("Key exchange error: {:?}", payload);
                    return Err(ClientError::ESSPError(ErrorType::KeyExchangeError));
                }
            }
        }
        reply
    }

    // pub fn coin_mech_options(&mut self) -> Result<Payload, ClientError> {}

    // pub fn get_build_revision(&mut self) -> Result<Payload, ClientError> {}

    // pub fn comms_pass_through(&mut self) -> Result<Payload, ClientError> {}

    // pub fn set_baud_rate(&mut self) -> Result<Payload, ClientError> {}

    // pub fn ssp_set_encryption_key(&mut self) -> Result<Payload, ClientError> {}

    // pub fn ssp_encryption_reset(&mut self) -> Result<Payload, ClientError> {}

    pub fn set_cashbox_payout_limit(&mut self, denom_vec: &Vec<CoinNumValue>) -> Result<Payload, ClientError> {
        // auto float
        let mut data = vec![denom_vec.len() as u8];

        for denom_data in denom_vec {
            let mut denom_enc = denom_data.encode();
            data.append(&mut denom_enc);
        }

        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SetCashboxPayoutLimit),
                                              data: data,
                                              encrypted: true,
                                          });

        self.send_and_check_reply(&message)
    }

    // ****************************************
    // ESSP commands for NV9 USB bill validator
    // ****************************************

    pub fn set_inhibits(&mut self, channels: [u8; 2]) -> Result<Payload, ClientError> {
        let message = self.create_message(Payload {
                                              code: Code::CommandCode(Command::SetInhibits),
                                              data: vec![channels[0], channels[1]],
                                              encrypted: true,
                                          });
        self.send_and_check_reply(&message)
    }
    //    pub fn display_on(){}
    //    pub fn display_off(){}
    //    pub fn reset(){}
    //    pub fn uint_data(){}
    //    pub fn channel_value_data(){}
    //    pub fn channel_security_data(){}
    //    pub fn last_reject_code(){}
    //    pub fn hold(){}
    //    pub fn get_counters(){}
    //    pub fn reset_counters(){}

    // ****************************************
    //         CUSTOM FUNCTIONS
    // ****************************************

    pub fn get_all_levels_sum(&mut self) -> Result<u32, ClientError> {
        let coin_num_values = self.get_all_levels()?;
        let mut sum = 0u32;
        for coin_num_value in coin_num_values {
            info!("{} {}: {} db", coin_num_value.value / self.scaling_factor, self.currency, coin_num_value.num);
            sum += coin_num_value.value / self.scaling_factor * coin_num_value.num as u32;
        }
        Ok(sum)
    }

    pub fn float_separately(&mut self, float_levels: &Vec<CoinNumValue>, test: bool) -> bool {

        let mut all_successful = true;
        for coin_num_value in float_levels {
            info!("Floating denom: {}", coin_num_value);
            if let Err(err) = self.float_by_denomination(vec![coin_num_value.clone()], test) {
                error!("Error during floating {}: {:?}", coin_num_value, err);
                all_successful = false;
            }
        }
        return all_successful;
    }

    pub fn set_auto_float_levels(&mut self, float_levels: &Vec<CoinNumValue>) -> Result<Payload, ClientError> {
        info!("Setting auto-float levels to: {}", float_levels.iter().format(", "));

        self.set_cashbox_payout_limit(float_levels)
    }
}
