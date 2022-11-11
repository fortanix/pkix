// As this common crate is used at a lot of places, didn't use use
// thiserror to keep dependencies to minimum.

use std::{borrow::Cow, fmt::Display};
use yasna::models::ObjectIdentifier;

#[derive(Debug)]
pub enum Error {
    Pkcs10(Pkcs10Error),
    Custom(Cow<'static, str>)
}

impl Error {
    pub fn custom(err: impl Into<Cow<'static, str>>) -> Self {
        Self::Custom(err.into())
    }
}

impl From<Pkcs10Error> for Error {
    fn from(pkcs10_error: Pkcs10Error) -> Self {
        Self::Pkcs10(pkcs10_error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs10(pkcs10_error) => write!(f, "{}", pkcs10_error),
            Self::Custom(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
pub enum Pkcs10Error {
    InvalidAttributeValue(/** attribute oid */ ObjectIdentifier),
    Custom(Cow<'static, str>),
}

impl Pkcs10Error {
    pub fn custom(err: impl Into<Cow<'static, str>>) -> Self {
        Self::Custom(err.into())
    }
}

impl Display for Pkcs10Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAttributeValue(oid) => write!(f, "invalid value for {} in PKCS #10 CSR attributes", oid),
            Self::Custom(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for Pkcs10Error {}
