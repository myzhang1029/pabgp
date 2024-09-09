//! Parse RIR statistics files into our internal data structures

// SPDX-License-Identifier: AGPL-3.0-or-later
// https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/

pub mod rirbase;

use crate::cidr::{Cidr, Cidr4, Cidr6};
use lazy_static::lazy_static;
use rirbase::{CountrySpec, RirName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::BufRead;

pub const ARIN_URL: &str = "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest";
pub const RIPE_URL: &str = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest";
pub const APNIC_URL: &str = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest";
pub const LACNIC_URL: &str = "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest";
pub const AFRINIC_URL: &str = "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest";
pub const SUPPORTED_VERSION: u32 = 2;

lazy_static! {
    static ref RIR_INFO: HashMap<RirName, &'static str> = [
        (RirName::Arin, ARIN_URL),
        (RirName::Ripencc, RIPE_URL),
        (RirName::Apnic, APNIC_URL),
        (RirName::Lacnic, LACNIC_URL),
        (RirName::Afrinic, AFRINIC_URL),
    ]
    .iter()
    .copied()
    .collect();
}

/// Error type for dealing with RIR statistics parsing
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP request returned status {0}")]
    HttpStatus(u16),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Ureq(#[from] Box<ureq::Error>),
    #[error("Unsupported RIR statistics version {0} from {1}")]
    UnsupportedVersion(u32, RirName),
    #[error("Unexpected RIR {0} (expected {1})")]
    UnexpectedRir(RirName, RirName),
    #[error("Invalid header line: {0}")]
    InvalidHeader(String),
}

/// Database diff
#[derive(Clone, Debug, Default)]
pub struct DatabaseDiff {
    /// IPv4 prefixes that were added
    pub new_ipv4: HashMap<CountrySpec, Vec<Cidr4>>,
    /// IPv4 prefixes that were removed
    pub withdrawn_ipv4: HashMap<CountrySpec, Vec<Cidr4>>,
    /// IPv6 prefixes that were added
    pub new_ipv6: HashMap<CountrySpec, Vec<Cidr6>>,
    /// IPv6 prefixes that were removed
    pub withdrawn_ipv6: HashMap<CountrySpec, Vec<Cidr6>>,
}

impl DatabaseDiff {
    /// Apply the diff to a database
    pub fn apply_to(self, db: &mut Database) {
        for (country, prefixes) in self.new_ipv4 {
            db.ipv4_prefixes
                .entry(country)
                .or_default()
                .extend(prefixes);
        }
        for (country, prefixes) in self.withdrawn_ipv4 {
            let db_prefixes = db.ipv4_prefixes.entry(country).or_default();
            db_prefixes.retain(|prefix| !prefixes.contains(prefix));
        }
        for (country, prefixes) in self.new_ipv6 {
            db.ipv6_prefixes
                .entry(country)
                .or_default()
                .extend(prefixes);
        }
        for (country, prefixes) in self.withdrawn_ipv6 {
            let db_prefixes = db.ipv6_prefixes.entry(country).or_default();
            db_prefixes.retain(|prefix| !prefixes.contains(prefix));
        }
    }

    /// Create a diff between two databases
    pub fn from_databases(old: &Database, new: &Database) -> Self {
        let mut diff = Self::default();
        for (country, prefixes) in &new.ipv4_prefixes {
            match old.ipv4_prefixes.get(country) {
                Some(old_prefixes) => {
                    let new_prefixes = prefixes
                        .iter()
                        .filter(|prefix| !old_prefixes.contains(prefix))
                        .copied()
                        .collect();
                    diff.new_ipv4.insert(*country, new_prefixes);
                    let withdrawn_prefixes = old_prefixes
                        .iter()
                        .filter(|prefix| !prefixes.contains(prefix))
                        .copied()
                        .collect();
                    diff.withdrawn_ipv4.insert(*country, withdrawn_prefixes);
                }
                None => {
                    diff.new_ipv4.insert(*country, prefixes.clone());
                }
            }
        }
        for (country, prefixes) in &new.ipv6_prefixes {
            match old.ipv6_prefixes.get(country) {
                Some(old_prefixes) => {
                    let new_prefixes = prefixes
                        .iter()
                        .filter(|prefix| !old_prefixes.contains(prefix))
                        .copied()
                        .collect();
                    diff.new_ipv6.insert(*country, new_prefixes);
                    let withdrawn_prefixes = old_prefixes
                        .iter()
                        .filter(|prefix| !prefixes.contains(prefix))
                        .copied()
                        .collect();
                    diff.withdrawn_ipv6.insert(*country, withdrawn_prefixes);
                }
                None => {
                    diff.new_ipv6.insert(*country, prefixes.clone());
                }
            }
        }
        diff
    }
}

/// Main database of RIR statistics (country to IP prefix)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Database {
    /// List of countries that we care about
    country_specs: Vec<CountrySpec>,
    /// Serial numbers of all fetched RIR statistics files
    serial_numbers: HashMap<RirName, u32>,
    /// Mapping from countries to delegated IPv4 prefixes
    ipv4_prefixes: HashMap<CountrySpec, Vec<Cidr4>>,
    /// Mapping from countries to delegated IPv6 prefixes
    ipv6_prefixes: HashMap<CountrySpec, Vec<Cidr6>>,
}

impl Database {
    /// Create a new empty database
    pub fn new(countries: Vec<CountrySpec>) -> Self {
        Self {
            country_specs: countries,
            serial_numbers: HashMap::new(),
            ipv4_prefixes: HashMap::new(),
            ipv6_prefixes: HashMap::new(),
        }
    }

    /// Update the database with a new country's statistics.
    pub fn update_all(&mut self) -> Result<(), Error> {
        let needed_rirs = self.needed_rirs();
        log::info!("Updating from RIRs: {:?}", needed_rirs);
        for rir in needed_rirs {
            let url = RIR_INFO[&rir];
            let response = ureq::get(url).call().map_err(Box::new)?;
            match response.status() {
                200 => self.update_from_response(response, rir)?,
                status => return Err(Error::HttpStatus(status)),
            }
        }
        Ok(())
    }

    /// Update the database with a new country's statistics.
    pub fn update_with_diff(&mut self) -> Result<DatabaseDiff, Error> {
        let mut new_db = Self::new(self.country_specs.clone());
        new_db.update_all()?;
        let diff = DatabaseDiff::from_databases(self, &new_db);
        *self = new_db;
        Ok(diff)
    }

    /// Get the IPv4 CIDR blocks for a country
    pub fn get_cidr4(&self, country: CountrySpec) -> Option<&Vec<Cidr4>> {
        self.ipv4_prefixes.get(&country)
    }

    /// Get the CIDR blocks for a country
    pub fn get_cidr6(&self, country: CountrySpec) -> Option<&Vec<Cidr6>> {
        self.ipv6_prefixes.get(&country)
    }

    /// Parse the response from a ureq request
    fn update_from_response(
        &mut self,
        response: ureq::Response,
        expected_rir: RirName,
    ) -> Result<(), Error> {
        let reader = std::io::BufReader::new(response.into_reader());
        let mut lines = reader.lines().enumerate();
        // Find the header line
        for (_, line) in &mut lines {
            if let Some(serial) = Self::check_header(&line?, expected_rir)? {
                if self.serial_numbers.get(&expected_rir) == Some(&serial) {
                    log::info!("Already up-to-date with {expected_rir}");
                    return Ok(());
                }
                self.serial_numbers.insert(expected_rir, serial);
                break;
            }
        }
        for (n, line) in lines {
            self.update_from_line(&line?);
            if n % 10000 == 0 {
                log::info!("Processed {n} lines from {expected_rir}");
            }
        }
        Ok(())
    }

    /// Parse and check the header of a RIR statistics file
    ///
    /// # Returns
    ///  - Ok(None) if the line is not a header line.
    ///  - Ok(Some(serial)) if the header is valid.
    ///  - Err(_) if the header is invalid.
    fn check_header(line: &str, expected_rir: RirName) -> Result<Option<u32>, Error> {
        if line.starts_with('#') {
            log::debug!("skipping line: {:?}", line);
            return Ok(None);
        }
        let parts = line.splitn(7, '|').collect::<Vec<_>>();
        // The first line should be a header line and this function should not be called after that.
        if parts.len() < 7 {
            return Err(Error::InvalidHeader(line.to_string()));
        }
        let version = parts[0]
            .parse()
            .map_err(|_| Error::InvalidHeader(line.to_string()))?;
        let rir = parts[1]
            .parse()
            .map_err(|_| Error::InvalidHeader(line.to_string()))?;
        let serial: u32 = parts[2]
            .parse()
            .map_err(|_| Error::InvalidHeader(line.to_string()))?;
        log::debug!("found header: {:?}", parts);
        if rir != expected_rir {
            return Err(Error::UnexpectedRir(rir, expected_rir));
        }
        if version != SUPPORTED_VERSION {
            return Err(Error::UnsupportedVersion(version, rir));
        }
        Ok(Some(serial))
    }

    /// Parse a single line from a RIR statistics file
    ///
    /// If the line does not represent an ipv4/ipv6 record, return None.
    /// Otherwise, return the country and CIDR block.
    fn parse_line(line: &str) -> Option<(CountrySpec, Cidr)> {
        if line.starts_with('#') {
            return None;
        }
        let parts = line.splitn(6, '|').collect::<Vec<_>>();
        if parts.len() < 6 {
            return None;
        }
        let rir = parts[0].parse().ok()?;
        let country_code = parts[1];
        let af = parts[2];
        // Err: Probably a unallocated block or a summary line
        let country = CountrySpec::new(rir, country_code).ok()?;
        match af {
            "ipv4" => {
                let addr = parts[3].parse().ok()?;
                let num_hosts = parts[4].parse().ok()?;
                let cidr = Cidr4::from_num_hosts(addr, num_hosts);
                Some((country, Cidr::V4(cidr)))
            }
            "ipv6" => {
                let addr = parts[3].parse().ok()?;
                let prefix_len = parts[4].parse().ok()?;
                let cidr = Cidr6::new(addr, prefix_len);
                Some((country, Cidr::V6(cidr)))
            }
            _ => None,
        }
    }

    /// Find out what RIR data we need to download
    fn needed_rirs(&self) -> HashSet<RirName> {
        self.country_specs.iter().map(CountrySpec::rir).collect()
    }

    /// Update from a single line of a RIR statistics file
    fn update_from_line(&mut self, line: &str) {
        if let Some((country, cidr)) = Self::parse_line(line) {
            if !self.country_specs.contains(&country) {
                // We don't care about this country
                return;
            }
            match cidr {
                Cidr::V4(cidr) => {
                    self.ipv4_prefixes.entry(country).or_default().push(cidr);
                }
                Cidr::V6(cidr) => {
                    self.ipv6_prefixes.entry(country).or_default().push(cidr);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn test_parse_line_v4() {
        let line = "apnic|CN|ipv4|103.37.72.0|1024|20140821|allocated";
        let (country, cidr) = Database::parse_line(line).unwrap();
        assert_eq!(country, "apnic:CN".parse().unwrap());
        let expected_addr: IpAddr = "103.37.72.0".parse().unwrap();
        assert_eq!(cidr.into_parts(), (expected_addr, 22));
    }

    #[test]
    fn test_parse_line_v6() {
        // Note that the extended format should also be supported.
        let line =
            "arin|US|ipv6|2605:4340::|32|20190509|allocated|85009a96f1ed4d3b37a1c73955633b73";
        let (country, cidr) = Database::parse_line(line).unwrap();
        assert_eq!(country, "arin:US".parse().unwrap());
        let expected_addr: IpAddr = "2605:4340::".parse().unwrap();
        assert_eq!(cidr.into_parts(), (expected_addr, 32));
    }

    #[test]
    fn test_parse_line_invalid() {
        // Test an unallocated block.
        let line = "lacnic||ipv4|45.68.184.0|256||reserved|";
        assert!(Database::parse_line(line).is_none());

        // Test a line that we don't care about.
        let line = "lacnic|*|ipv4|*|19862|summary";
        assert!(Database::parse_line(line).is_none());
    }

    #[test]
    #[cfg(feature = "test-real-internet")]
    fn test_update_all_cnv4() {
        let country = "apnic:CN".parse().unwrap();
        let mut db = Database::new(vec![country]);
        db.update_all().unwrap();
        assert!(!db.ipv4_prefixes.is_empty());
        let should_be_in = Cidr4::new("1.2.4.0".parse().unwrap(), 24);
        assert!(db.ipv4_prefixes[&country].contains(&should_be_in));
    }
}
