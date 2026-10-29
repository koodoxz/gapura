//! GeoIP Module
//!
//! Performs local IP lookups using MaxMind databases.

use anyhow::Result;
use maxminddb::Reader;
use std::net::IpAddr;
use std::path::Path;
use serde::Deserialize;

#[derive(Debug)]
pub struct GeoIpReader {
    reader: Reader<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct GeoLocation {
    pub country_code: String,
    pub region: Option<String>,
    pub city: Option<String>,
}

impl GeoIpReader {
    /// Load a MaxMind database from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    /// Lookup an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        let country: maxminddb::geoip2::Country = match self.reader.lookup(ip) {
            Ok(c) => c,
            Err(_) => return None,
        };

        let country_code = country.country?
            .iso_code?
            .to_string();

        Some(GeoLocation {
            country_code,
            region: None, // Requires City/Enterprise DB for full region info
            city: None,
        })
    }
}
