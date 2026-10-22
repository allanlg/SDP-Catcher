use serde::Serialize;
use std::fmt;

#[allow(clippy::upper_case_acronyms, dead_code)]
#[derive(Serialize, Clone, Debug, PartialEq)]
pub enum Manufacturer {
    Riedel,
    Audinate,
    Yamaha,
    Lawo,
    Merging,
    SSL,
    AllenHeath,
    Avid,
    Shure,
    Sennheiser,
    AudioTechnica,
    BlackmagicDesign,
    Focusrite,
    Genelec,
    Neumann,
    Apogee,
    Luminex,
    NetgearAV,
    DBAudiotechnik,
    LAco,
    MeyerSound,
    DirectOut,
    Digico,
    QSC,
    AxiaTelos,
    Wheatstone,
    RossVideo,
    Evertz,
    GrassValley,
    TSL,
    Calrec,
    ClearCom,
    RTS,
    BirdDog,
    Studer,
    Sonifex,
    BehringerMidas,
    SoundDevices,
    KlarkTeknik,
    Kramer,
    ATEN,
    Unknown,
}

impl fmt::Display for Manufacturer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Manufacturer::Riedel => "Riedel",
            Manufacturer::Audinate => "Audinate",
            Manufacturer::Yamaha => "Yamaha",
            Manufacturer::Lawo => "Lawo",
            Manufacturer::Merging => "Merging",
            Manufacturer::SSL => "SSL",
            Manufacturer::AllenHeath => "Allen & Heath",
            Manufacturer::Avid => "Avid",
            Manufacturer::Shure => "Shure",
            Manufacturer::Sennheiser => "Sennheiser",
            Manufacturer::AudioTechnica => "Audio-Technica",
            Manufacturer::BlackmagicDesign => "Blackmagic Design",
            Manufacturer::Focusrite => "Focusrite",
            Manufacturer::Genelec => "Genelec",
            Manufacturer::Neumann => "Neumann",
            Manufacturer::Apogee => "Apogee",
            Manufacturer::Luminex => "Luminex",
            Manufacturer::NetgearAV => "Netgear AV",
            Manufacturer::DBAudiotechnik => "d&b audiotechnik",
            Manufacturer::LAco => "L'Acoustics",
            Manufacturer::MeyerSound => "Meyer Sound",
            Manufacturer::DirectOut => "DirectOut",
            Manufacturer::Digico => "Digico",
            Manufacturer::QSC => "QSC",
            Manufacturer::AxiaTelos => "Axia/Telos",
            Manufacturer::Wheatstone => "Wheatstone",
            Manufacturer::RossVideo => "Ross Video",
            Manufacturer::Evertz => "Evertz",
            Manufacturer::GrassValley => "Grass Valley",
            Manufacturer::TSL => "TSL",
            Manufacturer::Calrec => "Calrec",
            Manufacturer::ClearCom => "Clear-Com",
            Manufacturer::RTS => "RTS",
            Manufacturer::BirdDog => "BirdDog",
            Manufacturer::Studer => "Studer",
            Manufacturer::Sonifex => "Sonifex",
            Manufacturer::BehringerMidas => "Behringer/Midas",
            Manufacturer::SoundDevices => "Sound Devices",
            Manufacturer::KlarkTeknik => "Klark Teknik",
            Manufacturer::Kramer => "Kramer",
            Manufacturer::ATEN => "ATEN",
            Manufacturer::Unknown => "Unknown",
        };
        formatter.write_str(name)
    }
}

impl Manufacturer {
    pub fn default_timeout_ms(&self, unknown_timeout_s: u64) -> u64 {
        match self {
            Manufacturer::Riedel => 12_000,
            Manufacturer::Audinate => 35_000,
            Manufacturer::Yamaha => 35_000,
            Manufacturer::Lawo => 35_000,
            Manufacturer::Merging => 35_000,
            Manufacturer::SSL => 35_000,
            Manufacturer::AllenHeath => 35_000,
            Manufacturer::Avid => 35_000,
            Manufacturer::Shure => 35_000,
            Manufacturer::Sennheiser => 35_000,
            Manufacturer::AudioTechnica => 35_000,
            Manufacturer::BlackmagicDesign => 40_000,
            Manufacturer::Focusrite => 35_000,
            Manufacturer::Genelec => 35_000,
            Manufacturer::Neumann => 35_000,
            Manufacturer::Apogee => 35_000,
            Manufacturer::Luminex => 40_000,
            Manufacturer::NetgearAV => 40_000,
            Manufacturer::DBAudiotechnik => 40_000,
            Manufacturer::LAco => 40_000,
            Manufacturer::MeyerSound => 40_000,
            Manufacturer::DirectOut => 35_000,
            Manufacturer::Digico => 35_000,
            Manufacturer::QSC => 35_000,
            Manufacturer::AxiaTelos => 35_000,
            Manufacturer::Wheatstone => 35_000,
            Manufacturer::RossVideo => 40_000,
            Manufacturer::Evertz => 40_000,
            Manufacturer::GrassValley => 40_000,
            Manufacturer::TSL => 40_000,
            Manufacturer::Calrec => 40_000,
            Manufacturer::ClearCom => 40_000,
            Manufacturer::RTS => 40_000,
            Manufacturer::BirdDog => 40_000,
            Manufacturer::Studer => 35_000,
            Manufacturer::Sonifex => 35_000,
            Manufacturer::BehringerMidas => 35_000,
            Manufacturer::SoundDevices => 35_000,
            Manufacturer::KlarkTeknik => 35_000,
            Manufacturer::Kramer => 35_000,
            Manufacturer::ATEN => 35_000,
            Manufacturer::Unknown => unknown_timeout_s.max(60) * 1000,
        }
    }
}

pub fn identify_manufacturer(id: &str) -> Manufacturer {
    let clean_id: String = id
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if clean_id.len() < 6 {
        return Manufacturer::Unknown;
    }
    let oui = &clean_id[0..6];

    match oui {
        "00197C" | "001ACA" | "F8DC7A" | "0007F5" => Manufacturer::Riedel,
        "001DC1" | "000FF2" => Manufacturer::Audinate,
        "00A0DE" | "AC44F2" | "F4D580" => Manufacturer::Yamaha,
        "30D659" => Manufacturer::Merging,
        "000B72" => Manufacturer::Lawo,
        "001E4C" => Manufacturer::DirectOut,
        "0050C2" => Manufacturer::Digico, // Bloc commun Audiotonix (Digico/SSL/A&H)
        "00602B" => Manufacturer::QSC,
        "00A07E" => Manufacturer::Avid,
        "00090B" => Manufacturer::AxiaTelos,
        "0009B8" => Manufacturer::RossVideo,
        "0005CA" => Manufacturer::Evertz,
        "000DEC" => Manufacturer::GrassValley,
        "000F72" => Manufacturer::TSL,
        "001D78" => Manufacturer::Calrec,
        "001A1E" => Manufacturer::ClearCom,
        "00136F" => Manufacturer::RTS,
        "000EDD" | "D834EE" | "9C431E" => Manufacturer::Shure,
        "001B66" => Manufacturer::Sennheiser, // Inclut Neumann
        "001D92" => Manufacturer::AudioTechnica,
        "7C2E0D" => Manufacturer::BlackmagicDesign,
        "0012A0" => Manufacturer::Focusrite,
        "AC4723" => Manufacturer::Genelec,
        "000A0E" => Manufacturer::Studer,
        "0090F5" => Manufacturer::Sonifex,
        "00066A" => Manufacturer::Apogee,
        "001564" => Manufacturer::BehringerMidas, // Inclut Klark Teknik
        "00196B" => Manufacturer::SoundDevices,
        "D0699E" => Manufacturer::Luminex,
        "E091F5" | "00146F" | "20E52A" => Manufacturer::NetgearAV,
        "00242C" => Manufacturer::DBAudiotechnik,
        "903EAB" => Manufacturer::LAco,
        "000D4B" => Manufacturer::MeyerSound,
        "000F7C" => Manufacturer::Kramer,
        "000BF6" => Manufacturer::ATEN,
        _ => Manufacturer::Unknown,
    }
}
