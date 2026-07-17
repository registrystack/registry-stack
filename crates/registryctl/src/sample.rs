use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;

use crate::stored_zip::{ZipEntry, ZipStoreWriter};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Sample {
    Benefits,
}

impl Sample {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::Benefits => "benefits",
        }
    }
}

#[derive(Clone, Copy)]
enum Cell {
    Text(&'static str),
    Integer(i64),
    Bool(bool),
}

pub fn write_benefits_workbook(path: &Path) -> Result<()> {
    let households_sheet = sheet_xml(&[
        &[
            Cell::Text("household_id"),
            Cell::Text("district"),
            Cell::Text("ward"),
            Cell::Text("poverty_band"),
            Cell::Text("household_status"),
            Cell::Text("registered_on"),
            Cell::Text("declared_member_count"),
            Cell::Text("address_line"),
        ],
        &[
            Cell::Text("hh-1001"),
            Cell::Text("south"),
            Cell::Text("ward_7"),
            Cell::Text("band_1"),
            Cell::Text("active"),
            Cell::Text("2024-01-12"),
            Cell::Integer(4),
            Cell::Text("595 River Rd, Southvale"),
        ],
        &[
            Cell::Text("hh-1002"),
            Cell::Text("north"),
            Cell::Text("ward_2"),
            Cell::Text("band_3"),
            Cell::Text("active"),
            Cell::Text("2023-11-03"),
            Cell::Integer(2),
            Cell::Text("524 Hill St, Northvale"),
        ],
        &[
            Cell::Text("hh-1003"),
            Cell::Text("east"),
            Cell::Text("ward_5"),
            Cell::Text("band_2"),
            Cell::Text("review_hold"),
            Cell::Text("2024-02-18"),
            Cell::Integer(3),
            Cell::Text("81 Market Ln, Eastport"),
        ],
        &[
            Cell::Text("hh-1004"),
            Cell::Text("west"),
            Cell::Text("ward_1"),
            Cell::Text("band_1"),
            Cell::Text("active"),
            Cell::Text("2022-08-30"),
            Cell::Integer(1),
            Cell::Text("140 Lakeside Ave, Westhaven"),
        ],
        &[
            Cell::Text("hh-1005"),
            Cell::Text("south"),
            Cell::Text("ward_8"),
            Cell::Text("band_2"),
            Cell::Text("closed"),
            Cell::Text("2021-04-22"),
            Cell::Integer(1),
            Cell::Text("22 Orchard Ct, Southvale"),
        ],
        &[
            Cell::Text("hh-1006"),
            Cell::Text("north"),
            Cell::Text("ward_3"),
            Cell::Text("band_1"),
            Cell::Text("active"),
            Cell::Text("2024-05-09"),
            Cell::Integer(1),
            Cell::Text("9 Cedar Loop, Northvale"),
        ],
    ]);
    let persons_sheet = sheet_xml(&[
        &[
            Cell::Text("person_id"),
            Cell::Text("household_id"),
            Cell::Text("given_name"),
            Cell::Text("family_name"),
            Cell::Text("date_of_birth"),
            Cell::Text("age_band"),
            Cell::Text("relationship_to_head"),
            Cell::Text("registration_status"),
            Cell::Text("eligibility_status"),
            Cell::Text("is_primary_applicant"),
            Cell::Text("national_id"),
        ],
        &[
            Cell::Text("per-2001"),
            Cell::Text("hh-1001"),
            Cell::Text("Fae"),
            Cell::Text("Elm"),
            Cell::Text("1989-05-14"),
            Cell::Text("35-49"),
            Cell::Text("head"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(true),
            Cell::Text("FAKE-856648"),
        ],
        &[
            Cell::Text("per-2002"),
            Cell::Text("hh-1001"),
            Cell::Text("Jo"),
            Cell::Text("Elm"),
            Cell::Text("2019-02-03"),
            Cell::Text("5-17"),
            Cell::Text("child"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(false),
            Cell::Text("FAKE-806707"),
        ],
        &[
            Cell::Text("per-2003"),
            Cell::Text("hh-1001"),
            Cell::Text("Kai"),
            Cell::Text("Elm"),
            Cell::Text("1954-09-21"),
            Cell::Text("65+"),
            Cell::Text("parent"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(false),
            Cell::Text("FAKE-219346"),
        ],
        &[
            Cell::Text("per-2004"),
            Cell::Text("hh-1001"),
            Cell::Text("Mina"),
            Cell::Text("Elm"),
            Cell::Text("1991-11-10"),
            Cell::Text("35-49"),
            Cell::Text("spouse"),
            Cell::Text("active"),
            Cell::Text("pending_review"),
            Cell::Bool(false),
            Cell::Text("FAKE-331902"),
        ],
        &[
            Cell::Text("per-2005"),
            Cell::Text("hh-1002"),
            Cell::Text("Dee"),
            Cell::Text("Iron"),
            Cell::Text("1984-01-28"),
            Cell::Text("35-49"),
            Cell::Text("head"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(true),
            Cell::Text("FAKE-748201"),
        ],
        &[
            Cell::Text("per-2006"),
            Cell::Text("hh-1002"),
            Cell::Text("Ari"),
            Cell::Text("Iron"),
            Cell::Text("2016-07-18"),
            Cell::Text("5-17"),
            Cell::Text("child"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(false),
            Cell::Text("FAKE-671240"),
        ],
        &[
            Cell::Text("per-2007"),
            Cell::Text("hh-1003"),
            Cell::Text("Nia"),
            Cell::Text("Stone"),
            Cell::Text("1998-03-05"),
            Cell::Text("18-34"),
            Cell::Text("head"),
            Cell::Text("pending"),
            Cell::Text("pending_review"),
            Cell::Bool(true),
            Cell::Text("FAKE-503118"),
        ],
        &[
            Cell::Text("per-2008"),
            Cell::Text("hh-1003"),
            Cell::Text("Sol"),
            Cell::Text("Stone"),
            Cell::Text("2022-12-12"),
            Cell::Text("0-4"),
            Cell::Text("child"),
            Cell::Text("pending"),
            Cell::Text("pending_review"),
            Cell::Bool(false),
            Cell::Text("FAKE-663910"),
        ],
        &[
            Cell::Text("per-2009"),
            Cell::Text("hh-1003"),
            Cell::Text("Ren"),
            Cell::Text("Stone"),
            Cell::Text("1970-06-30"),
            Cell::Text("50-64"),
            Cell::Text("parent"),
            Cell::Text("active"),
            Cell::Text("ineligible"),
            Cell::Bool(false),
            Cell::Text("FAKE-447120"),
        ],
        &[
            Cell::Text("per-2010"),
            Cell::Text("hh-1004"),
            Cell::Text("Ivo"),
            Cell::Text("Reed"),
            Cell::Text("1957-04-02"),
            Cell::Text("65+"),
            Cell::Text("head"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(true),
            Cell::Text("FAKE-990231"),
        ],
        &[
            Cell::Text("per-2011"),
            Cell::Text("hh-1005"),
            Cell::Text("Uma"),
            Cell::Text("Vale"),
            Cell::Text("1993-08-16"),
            Cell::Text("18-34"),
            Cell::Text("head"),
            Cell::Text("closed"),
            Cell::Text("ineligible"),
            Cell::Bool(true),
            Cell::Text("FAKE-125904"),
        ],
        &[
            Cell::Text("per-2012"),
            Cell::Text("hh-1006"),
            Cell::Text("Lina"),
            Cell::Text("Moss"),
            Cell::Text("1982-10-25"),
            Cell::Text("35-49"),
            Cell::Text("head"),
            Cell::Text("active"),
            Cell::Text("eligible"),
            Cell::Bool(true),
            Cell::Text("FAKE-775120"),
        ],
    ]);
    let applications_sheet = sheet_xml(&[
        &[
            Cell::Text("application_id"),
            Cell::Text("household_id"),
            Cell::Text("applicant_person_id"),
            Cell::Text("program"),
            Cell::Text("application_date"),
            Cell::Text("intake_channel"),
            Cell::Text("office_code"),
            Cell::Text("application_status"),
            Cell::Text("decision"),
            Cell::Text("benefit_level"),
            Cell::Text("review_due_on"),
            Cell::Text("identity_verified"),
            Cell::Text("residence_verified"),
            Cell::Text("consent_reference"),
        ],
        &[
            Cell::Text("app-3001"),
            Cell::Text("hh-1001"),
            Cell::Text("per-2001"),
            Cell::Text("cash_transfer"),
            Cell::Text("2024-01-20"),
            Cell::Text("office"),
            Cell::Text("SOUTH-01"),
            Cell::Text("approved"),
            Cell::Text("eligible"),
            Cell::Text("enhanced"),
            Cell::Text("2026-01-20"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9001"),
        ],
        &[
            Cell::Text("app-3002"),
            Cell::Text("hh-1002"),
            Cell::Text("per-2005"),
            Cell::Text("food_support"),
            Cell::Text("2024-02-10"),
            Cell::Text("mobile_team"),
            Cell::Text("NORTH-02"),
            Cell::Text("approved"),
            Cell::Text("eligible"),
            Cell::Text("standard"),
            Cell::Text("2025-08-10"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9002"),
        ],
        &[
            Cell::Text("app-3003"),
            Cell::Text("hh-1003"),
            Cell::Text("per-2007"),
            Cell::Text("cash_transfer"),
            Cell::Text("2024-03-05"),
            Cell::Text("partner_referral"),
            Cell::Text("EAST-01"),
            Cell::Text("under_review"),
            Cell::Text("pending_review"),
            Cell::Text("none"),
            Cell::Text("2024-06-30"),
            Cell::Bool(true),
            Cell::Bool(false),
            Cell::Text("consent-9003"),
        ],
        &[
            Cell::Text("app-3004"),
            Cell::Text("hh-1004"),
            Cell::Text("per-2010"),
            Cell::Text("disability_support"),
            Cell::Text("2023-09-15"),
            Cell::Text("office"),
            Cell::Text("WEST-01"),
            Cell::Text("approved"),
            Cell::Text("eligible"),
            Cell::Text("enhanced"),
            Cell::Text("2025-09-15"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9004"),
        ],
        &[
            Cell::Text("app-3005"),
            Cell::Text("hh-1005"),
            Cell::Text("per-2011"),
            Cell::Text("emergency_grant"),
            Cell::Text("2023-04-25"),
            Cell::Text("online"),
            Cell::Text("SOUTH-01"),
            Cell::Text("closed"),
            Cell::Text("ineligible"),
            Cell::Text("none"),
            Cell::Text("2023-07-25"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9005"),
        ],
        &[
            Cell::Text("app-3006"),
            Cell::Text("hh-1006"),
            Cell::Text("per-2012"),
            Cell::Text("cash_transfer"),
            Cell::Text("2024-05-12"),
            Cell::Text("office"),
            Cell::Text("NORTH-02"),
            Cell::Text("submitted"),
            Cell::Text("pending_review"),
            Cell::Text("none"),
            Cell::Text("2024-08-12"),
            Cell::Bool(false),
            Cell::Bool(true),
            Cell::Text("consent-9006"),
        ],
        &[
            Cell::Text("app-3007"),
            Cell::Text("hh-1001"),
            Cell::Text("per-2001"),
            Cell::Text("school_meals"),
            Cell::Text("2024-06-01"),
            Cell::Text("office"),
            Cell::Text("SOUTH-01"),
            Cell::Text("approved"),
            Cell::Text("eligible"),
            Cell::Text("standard"),
            Cell::Text("2026-06-01"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9007"),
        ],
        &[
            Cell::Text("app-3008"),
            Cell::Text("hh-1002"),
            Cell::Text("per-2005"),
            Cell::Text("cash_transfer"),
            Cell::Text("2024-06-15"),
            Cell::Text("mobile_team"),
            Cell::Text("NORTH-02"),
            Cell::Text("approved"),
            Cell::Text("eligible"),
            Cell::Text("standard"),
            Cell::Text("2026-06-15"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9008"),
        ],
        &[
            Cell::Text("app-3009"),
            Cell::Text("hh-1003"),
            Cell::Text("per-2007"),
            Cell::Text("food_support"),
            Cell::Text("2024-06-18"),
            Cell::Text("partner_referral"),
            Cell::Text("EAST-01"),
            Cell::Text("approved"),
            Cell::Text("eligible"),
            Cell::Text("standard"),
            Cell::Text("2026-06-18"),
            Cell::Bool(true),
            Cell::Bool(true),
            Cell::Text("consent-9009"),
        ],
    ]);

    let entries = [
        ZipEntry::new("[Content_Types].xml", CONTENT_TYPES.as_bytes()),
        ZipEntry::new("_rels/.rels", ROOT_RELS.as_bytes()),
        ZipEntry::new("xl/workbook.xml", WORKBOOK.as_bytes()),
        ZipEntry::new("xl/_rels/workbook.xml.rels", WORKBOOK_RELS.as_bytes()),
        ZipEntry::new("xl/worksheets/sheet1.xml", households_sheet.as_bytes()),
        ZipEntry::new("xl/worksheets/sheet2.xml", persons_sheet.as_bytes()),
        ZipEntry::new("xl/worksheets/sheet3.xml", applications_sheet.as_bytes()),
    ];
    ZipStoreWriter::write(path, &entries)
}

fn sheet_xml(rows: &[&[Cell]]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
"#,
    );
    for (row_idx, row) in rows.iter().enumerate() {
        let row_number = row_idx + 1;
        xml.push_str(&format!("    <row r=\"{row_number}\">\n"));
        for (col_idx, cell) in row.iter().enumerate() {
            let reference = cell_reference(col_idx, row_number);
            write_cell(&mut xml, &reference, *cell);
        }
        xml.push_str("    </row>\n");
    }
    xml.push_str("  </sheetData>\n</worksheet>");
    xml
}

fn write_cell(xml: &mut String, reference: &str, cell: Cell) {
    match cell {
        Cell::Text(value) => {
            xml.push_str(&format!(
                "      <c r=\"{reference}\" t=\"inlineStr\"><is><t>{}</t></is></c>\n",
                escape_xml(value)
            ));
        }
        Cell::Integer(value) => {
            xml.push_str(&format!("      <c r=\"{reference}\"><v>{value}</v></c>\n"));
        }
        Cell::Bool(value) => {
            let value = if value { 1 } else { 0 };
            xml.push_str(&format!(
                "      <c r=\"{reference}\" t=\"b\"><v>{value}</v></c>\n"
            ));
        }
    }
}

fn cell_reference(mut col_idx: usize, row_number: usize) -> String {
    let mut letters = Vec::new();
    loop {
        let remainder = col_idx % 26;
        letters.push((b'A' + remainder as u8) as char);
        col_idx /= 26;
        if col_idx == 0 {
            break;
        }
        col_idx -= 1;
    }
    letters.iter().rev().collect::<String>() + row_number.to_string().as_str()
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#;

const ROOT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;

const WORKBOOK: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Households" sheetId="1" r:id="rId1"/>
    <sheet name="Persons" sheetId="2" r:id="rId2"/>
    <sheet name="Applications" sheetId="3" r:id="rId3"/>
  </sheets>
</workbook>"#;

const WORKBOOK_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>
</Relationships>"#;
