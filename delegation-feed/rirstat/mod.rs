//! Parse RIR statistics files into our internal data structures

// SPDX-License-Identifier: AGPL-3.0-or-later
// https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/

pub mod rirbase;

use lazy_static::lazy_static;
use pabgp::cidr::{Cidr, Cidr4, Cidr6};
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
pub const SUPPORTED_VERSIONS: [&str; 2] = ["2", "2.3"];

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
    UnsupportedVersion(String, RirName),
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

    /// Compute the diff between two databases
    pub fn compute_diff(old: &Database, new: &Database, updated_rirs: &HashSet<RirName>) -> Self {
        let mut diff = Self::default();
        for (country, prefixes) in &new.ipv4_prefixes {
            if !updated_rirs.contains(&country.rir()) {
                // This country was not updated
                continue;
            }
            let old_prefixes = old.ipv4_prefixes.get(country);
            let new_prefixes: Vec<Cidr4> = prefixes
                .iter()
                // Keep those that are not in the old prefixes
                .filter(|prefix| old_prefixes.map_or(true, |p| !p.contains(prefix)))
                .copied()
                .collect();
            let withdrawn_prefixes: Vec<Cidr4> = old_prefixes.map_or(vec![], |p| {
                p.iter()
                    // Keep those that are not in the new prefixes
                    .filter(|prefix| !prefixes.contains(prefix))
                    .copied()
                    .collect()
            });
            if !new_prefixes.is_empty() {
                diff.new_ipv4.insert(*country, new_prefixes);
            }
            if !withdrawn_prefixes.is_empty() {
                diff.withdrawn_ipv4.insert(*country, withdrawn_prefixes);
            }
        }
        for (country, prefixes) in &new.ipv6_prefixes {
            if !updated_rirs.contains(&country.rir()) {
                // This country was not updated
                continue;
            }
            let old_prefixes = old.ipv6_prefixes.get(country);
            let new_prefixes: Vec<Cidr6> = prefixes
                .iter()
                // Keep those that are not in the old prefixes
                .filter(|prefix| old_prefixes.map_or(true, |p| !p.contains(prefix)))
                .copied()
                .collect();
            let withdrawn_prefixes: Vec<Cidr6> = old_prefixes.map_or(vec![], |p| {
                p.iter()
                    // Keep those that are not in the new prefixes
                    .filter(|prefix| !prefixes.contains(prefix))
                    .copied()
                    .collect()
            });
            if !new_prefixes.is_empty() {
                diff.new_ipv6.insert(*country, new_prefixes);
            }
            if !withdrawn_prefixes.is_empty() {
                diff.withdrawn_ipv6.insert(*country, withdrawn_prefixes);
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
    serial_numbers: HashMap<RirName, u64>,
    /// Whether to parse IPv4 prefixes
    enable_ipv4: bool,
    /// Mapping from countries to delegated IPv4 prefixes
    ipv4_prefixes: HashMap<CountrySpec, Vec<Cidr4>>,
    /// Whether to parse IPv6 prefixes
    enable_ipv6: bool,
    /// Mapping from countries to delegated IPv6 prefixes
    ipv6_prefixes: HashMap<CountrySpec, Vec<Cidr6>>,
}

impl Database {
    /// Create a new empty database
    pub fn new(countries: Vec<CountrySpec>, enable_ipv4: bool, enable_ipv6: bool) -> Self {
        Self {
            country_specs: countries,
            serial_numbers: HashMap::new(),
            enable_ipv4,
            ipv4_prefixes: HashMap::new(),
            enable_ipv6,
            ipv6_prefixes: HashMap::new(),
        }
    }

    /// Update the database with a new country's statistics.
    pub fn update_all(&mut self) -> Result<HashSet<RirName>, Error> {
        let needed_rirs = self.needed_rirs();
        let mut updated = HashSet::new();
        log::info!("Updating from RIRs: {:?}", needed_rirs);
        for rir in needed_rirs {
            let url = RIR_INFO[&rir];
            let response = ureq::get(url).call().map_err(Box::new)?;
            match response.status() {
                200 => {
                    if self.update_from_response(response, rir)? {
                        log::info!("Updated database with {rir}");
                        updated.insert(rir);
                    }
                }
                status => return Err(Error::HttpStatus(status)),
            }
        }
        Ok(updated)
    }

    /// Update the database with a new country's statistics.
    pub fn update_with_diff(&mut self) -> Result<DatabaseDiff, Error> {
        let mut new_db = Self::new(
            self.country_specs.clone(),
            self.enable_ipv4,
            self.enable_ipv6,
        );
        // Copy the serial numbers from the old database
        new_db.serial_numbers.clone_from(&self.serial_numbers);
        let updated_rirs = new_db.update_all()?;
        let diff = DatabaseDiff::compute_diff(self, &new_db, &updated_rirs);
        let old_db = std::mem::replace(self, new_db);
        // Insert unaffected countries back into the new database
        for (country, prefixes) in old_db.ipv4_prefixes {
            if !updated_rirs.contains(&country.rir()) {
                self.ipv4_prefixes.insert(country, prefixes);
            }
        }
        for (country, prefixes) in old_db.ipv6_prefixes {
            if !updated_rirs.contains(&country.rir()) {
                self.ipv6_prefixes.insert(country, prefixes);
            }
        }
        Ok(diff)
    }

    /// Parse the response from a ureq request
    ///
    /// # Returns
    /// - Ok(true) if the database was updated.
    /// - Ok(false) if the database was already up-to-date.
    /// - Err(_) if the response was invalid.
    fn update_from_response(
        &mut self,
        response: ureq::Response,
        expected_rir: RirName,
    ) -> Result<bool, Error> {
        let reader = std::io::BufReader::new(response.into_reader());
        let mut lines = reader.lines().enumerate();
        // Find the header line
        for (_, line) in &mut lines {
            if let Some(serial) = Self::check_header(&line?, expected_rir)? {
                let prev_serial = self.serial_numbers.get(&expected_rir);
                log::debug!(
                    "Found serial number {serial} for {expected_rir}, previous: {prev_serial:?}"
                );
                if prev_serial == Some(&serial) {
                    log::info!("Already up-to-date with {expected_rir}");
                    return Ok(false);
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
        Ok(true)
    }

    /// Parse and check the header of a RIR statistics file
    ///
    /// # Returns
    ///  - Ok(None) if the line is not a header line.
    ///  - Ok(Some(serial)) if the header is valid.
    ///  - Err(_) if the header is invalid.
    fn check_header(line: &str, expected_rir: RirName) -> Result<Option<u64>, Error> {
        if line.starts_with('#') {
            log::debug!("skipping line: {:?}", line);
            return Ok(None);
        }
        let parts = line.splitn(7, '|').collect::<Vec<_>>();
        // The first line should be a header line and this function should not be called after that.
        if parts.len() < 7 {
            return Err(Error::InvalidHeader(line.to_string()));
        }
        let version = parts[0];
        let rir = parts[1]
            .parse()
            .map_err(|_| Error::InvalidHeader(line.to_string()))?;
        let serial: u64 = parts[2]
            .parse()
            .map_err(|_| Error::InvalidHeader(line.to_string()))?;
        log::debug!("found header: {:?}", parts);
        if rir != expected_rir {
            return Err(Error::UnexpectedRir(rir, expected_rir));
        }
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(Error::UnsupportedVersion(version.to_string(), rir));
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
                    if self.enable_ipv4 {
                        self.ipv4_prefixes.entry(country).or_default().push(cidr);
                    }
                }
                Cidr::V6(cidr) => {
                    if self.enable_ipv6 {
                        self.ipv6_prefixes.entry(country).or_default().push(cidr);
                    }
                }
            }
        }
    }

    /// Consumes the database and returns the country to CIDR maps
    pub fn into_prefixes(
        self,
    ) -> (
        HashMap<CountrySpec, Vec<Cidr4>>,
        HashMap<CountrySpec, Vec<Cidr6>>,
    ) {
        (self.ipv4_prefixes, self.ipv6_prefixes)
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
    fn test_update_all_jp() {
        let country = "apnic:JP".parse().unwrap();
        let mut db = Database::new(vec![country], true, true);
        db.update_all().unwrap();
        assert!(!db.ipv4_prefixes.is_empty());
        let should_be_in = Cidr4::new("43.252.240.0".parse().unwrap(), 22);
        assert!(db.ipv4_prefixes[&country].contains(&should_be_in));
        assert!(!db.ipv6_prefixes.is_empty());
        let should_be_in = Cidr6::new("2001:44a8::".parse().unwrap(), 32);
        assert!(db.ipv6_prefixes[&country].contains(&should_be_in));
    }

    #[test]
    #[cfg(feature = "test-real-internet")]
    fn test_update_all_ca() {
        let country = "arin:CA".parse().unwrap();
        let mut db = Database::new(vec![country], true, true);
        db.update_all().unwrap();
        assert!(!db.ipv4_prefixes.is_empty());
        let should_be_in = Cidr4::new("192.174.4.0".parse().unwrap(), 22);
        assert!(db.ipv4_prefixes[&country].contains(&should_be_in));
        assert!(!db.ipv6_prefixes.is_empty());
        let should_be_in = Cidr6::new("2604:cfc0::".parse().unwrap(), 32);
        assert!(db.ipv6_prefixes[&country].contains(&should_be_in));
    }
}
