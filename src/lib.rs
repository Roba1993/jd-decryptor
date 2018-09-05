//! A simple library to decode JDownloader .ejs files.
//!
//! ## Usage
//! Add `jd_decrypter` as a dependency in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! jd-decrypter = "0.1.0"
//! ```
//!
//! Use the `jd_decrypter::Decryptor` to decrypt a .ejs file:
//!
//! ```rust
//! extern crate jd_decrypter;
//! 
//! use std::env;
//! use jd_decrypter::JdAccountList;
//! 
//! fn main() {
//!     // loop over all arguments for the programm
//!     // skip the first one because it's the programm
//!     // own name
//!     for arg in env::args().skip(1) {
//!         // hand over the file path
//!         let dlc = JdAccountList::from_file(arg);
//! 
//!         // print the result
//!         println!("Accounts: {:?}", dlc);
//!     }
//! }
//! ```
//!
//! ## License
//! Distributed under the MIT License.

#![allow(renamed_and_removed_lints)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate crypto;
extern crate serde;
extern crate serde_json;

use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer};
use std::fs::File;
use std::io::Read;
use std::collections::HashMap;

use serde_json::{Value};

const ACCOUNT_KEY: [u8; 16] = [1, 6, 4, 5, 2, 7, 4, 3, 12, 61, 14, 75, 254, 249, 212, 33]; // AccountSettings.java

//const auth_key: [u8; 16] = [2, 4, 4, 5, 2, 7, 4, 3, 12, 61, 14, 75, 254, 249, 212, 33];	    // AuthenticationControllerSettings.java
//const proxy_key: [u8;16] = [1, 3, 17, 1, 1, 84, 1, 1, 1, 2, 193, 1, 17, 1, 34, 244];		// ProxySelectorImpl.java
//const crawler_key: [u8;16] = [1, 3, 17, 1, 1, 84, 1, 1, 1, 1, 18, 1, 1, 1, 34, 1];  		// CrawlerPluginController.java
//const config_key: [u8;16 ] = [1, 2, 17, 1, 1, 84, 1, 1, 1, 1, 18, 1, 1, 1, 34, 1];			// JSonStorage.java, SubConfiguration.java
//const file_key: [u8;16] = [0, 2, 17, 1, 1, 84, 2, 1, 1, 1, 18, 1, 1, 1, 18, 1];    		    // ExtFileChooseIdConfig.java
//const dload_key: [u8;16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];		    // DownloadLinkStorable.java

/// JdAccountlist has all accounts grouped by name
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JdAccountList(HashMap<String, Vec<JdAccount>>);

/// Struct to decode the .dlc file or data into an readable format.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JdAccount {
    pub properties: Value,
    pub hoster: String,
    #[serde(rename = "maxSimultanDownloads")]
    pub max_simultan_downloads: isize,
    pub password : String,
    #[serde(rename = "infoProperties")]
    pub info_properties: Value,
    #[serde(rename = "createTime")]
    pub create_time: isize,
    #[serde(rename = "trafficLeft")]
    pub traffic_left: isize,
    #[serde(rename = "trafficMax")]
    pub traffic_max: isize,
    #[serde(rename = "validUntil")]
    pub valid_until: isize,
    pub active: bool,
    pub enabled: bool,
    #[serde(rename = "trafficUnlimited")]
    pub traffic_unlimited: bool,
    pub specialtraffic: bool,
    pub user: String,
    #[serde(rename = "concurrentUsePossible")]
    pub concurrent_use_possible: bool,
    pub id: usize,
    #[serde(rename = "errorType")]
    pub error_type: Option<String>,
    #[serde(rename = "errorString")]
    pub error_string: Option<String>,
}

impl JdAccountList {
    /// Decrypt a specified .dlc file
    pub fn from_file<P: Into<String>>(path: P) -> Result<JdAccountList> {
        // read the file
        let mut file = File::open(path.into())?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        // return the decrypted dlc package
        JdAccountList::from_data(&data)
    }

    /// Decrypt the contet of a .dlc file.
    pub fn from_data(data: &[u8]) -> Result<JdAccountList> {
        let mut data = decrypt_raw_data(data, &ACCOUNT_KEY, &ACCOUNT_KEY)?;

        // remove all data from the end of the string until we reach the json data
        while data.last().ok_or("No decrypted data")? != &0x7Du8 {
            data.pop().ok_or("No decrypted data in loop")?;
        }

        // get the string
        let data = std::str::from_utf8(&data)?;
        let al: JdAccountList = serde_json::from_str(data)?;
        Ok(al)
    }

    /// Get a reference to the internal HashMap with all accounts
    pub fn as_ref(&self) -> &HashMap<String, Vec<JdAccount>> {
        &self.0
    }
}

/// Decrypt data by the given key and iv.
fn decrypt_raw_data(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    // create decryptor and set keys & values
    let mut decryptor = aes_cbc_decryptor(aes::KeySize::KeySize128, key, iv, blockmodes::NoPadding);

    // create the buffer objects
    let mut buffer = [0; 4096];
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut writ_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    let mut result = Vec::new();

    loop {
        // decrypt the buffer
        if decryptor
            .decrypt(&mut read_buffer, &mut writ_buffer, true)
            .is_err()
        {
            bail!("Can't decrypt");
        }

        // when the write_buffer is empty, the decryption is finished
        if writ_buffer.is_empty() {
            break;
        }

        // add the encrypted data to the result
        result.extend_from_slice(writ_buffer.take_read_buffer().take_remaining());
    }

    // remove tailing zeros
    result.retain(|x| *x != 0 as u8);

    return Ok(result);
}

// use only for crypto
use crypto::aes::KeySize;
use crypto::aessafe;
use crypto::blockmodes::{CbcDecryptor, PaddingProcessor};
use crypto::symmetriccipher::Decryptor;

/// Reimplementation of the aes cbc decryptor function from Rust-Crypto.
///
/// This function always use the software decryption insted of the hardware one.
/// This can have a samll speed impact. But the hardware decryption fails for
/// musl-docker builds and is shutting down any programm without a warning.
///
/// To garuntee the stability of the dlc-decryptor, we use the software decryption.
fn aes_cbc_decryptor<X: PaddingProcessor + Send + 'static>(
    key_size: KeySize,
    key: &[u8],
    iv: &[u8],
    padding: X,
) -> Box<Decryptor + 'static> {
    match key_size {
        KeySize::KeySize128 => {
            let aes_dec = aessafe::AesSafe128Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<Decryptor + 'static>
        }
        KeySize::KeySize192 => {
            let aes_dec = aessafe::AesSafe192Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<Decryptor + 'static>
        }
        KeySize::KeySize256 => {
            let aes_dec = aessafe::AesSafe256Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<Decryptor + 'static>
        }
    }
}

// Error_Chain error handling
error_chain!{

    types {
        Error, ErrorKind, ResultExt, Result;
    }

    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
        Utf8(::std::str::Utf8Error);
        FromUtf8(::std::string::FromUtf8Error);
        SerdeJson(::serde_json::Error);
    }
}
