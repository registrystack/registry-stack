use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;

use crate::stored_zip::{ZipEntry, ZipStoreWriter};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Sample {
    Benefits,
}

pub fn write_benefits_workbook(path: &Path) -> Result<()> {
    let entries = [
        ZipEntry::new("[Content_Types].xml", CONTENT_TYPES.as_bytes()),
        ZipEntry::new("_rels/.rels", ROOT_RELS.as_bytes()),
        ZipEntry::new("xl/workbook.xml", WORKBOOK.as_bytes()),
        ZipEntry::new("xl/_rels/workbook.xml.rels", WORKBOOK_RELS.as_bytes()),
        ZipEntry::new("xl/worksheets/sheet1.xml", HOUSEHOLDS_SHEET.as_bytes()),
        ZipEntry::new("xl/worksheets/sheet2.xml", PERSONS_SHEET.as_bytes()),
    ];
    ZipStoreWriter::write(path, &entries)
}

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
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
  </sheets>
</workbook>"#;

const WORKBOOK_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>"#;

const HOUSEHOLDS_SHEET: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr"><is><t>household_id</t></is></c>
      <c r="B1" t="inlineStr"><is><t>district</t></is></c>
      <c r="C1" t="inlineStr"><is><t>poverty_band</t></is></c>
      <c r="D1" t="inlineStr"><is><t>address_line</t></is></c>
    </row>
    <row r="2">
      <c r="A2" t="inlineStr"><is><t>hh-1001</t></is></c>
      <c r="B2" t="inlineStr"><is><t>south</t></is></c>
      <c r="C2" t="inlineStr"><is><t>band_1</t></is></c>
      <c r="D2" t="inlineStr"><is><t>595 Fake St, southvale</t></is></c>
    </row>
    <row r="3">
      <c r="A3" t="inlineStr"><is><t>hh-1002</t></is></c>
      <c r="B3" t="inlineStr"><is><t>north</t></is></c>
      <c r="C3" t="inlineStr"><is><t>band_3</t></is></c>
      <c r="D3" t="inlineStr"><is><t>524 Fake St, northvale</t></is></c>
    </row>
  </sheetData>
</worksheet>"#;

const PERSONS_SHEET: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr"><is><t>person_id</t></is></c>
      <c r="B1" t="inlineStr"><is><t>household_id</t></is></c>
      <c r="C1" t="inlineStr"><is><t>age_band</t></is></c>
      <c r="D1" t="inlineStr"><is><t>eligibility_status</t></is></c>
      <c r="E1" t="inlineStr"><is><t>full_name</t></is></c>
      <c r="F1" t="inlineStr"><is><t>national_id</t></is></c>
    </row>
    <row r="2">
      <c r="A2" t="inlineStr"><is><t>per-2001</t></is></c>
      <c r="B2" t="inlineStr"><is><t>hh-1001</t></is></c>
      <c r="C2" t="inlineStr"><is><t>0-4</t></is></c>
      <c r="D2" t="inlineStr"><is><t>eligible</t></is></c>
      <c r="E2" t="inlineStr"><is><t>Fae Elm</t></is></c>
      <c r="F2" t="inlineStr"><is><t>FAKE-856648</t></is></c>
    </row>
    <row r="3">
      <c r="A3" t="inlineStr"><is><t>per-2002</t></is></c>
      <c r="B3" t="inlineStr"><is><t>hh-1001</t></is></c>
      <c r="C3" t="inlineStr"><is><t>65+</t></is></c>
      <c r="D3" t="inlineStr"><is><t>eligible</t></is></c>
      <c r="E3" t="inlineStr"><is><t>Jo Apple</t></is></c>
      <c r="F3" t="inlineStr"><is><t>FAKE-806707</t></is></c>
    </row>
    <row r="4">
      <c r="A4" t="inlineStr"><is><t>per-2003</t></is></c>
      <c r="B4" t="inlineStr"><is><t>hh-1002</t></is></c>
      <c r="C4" t="inlineStr"><is><t>18-64</t></is></c>
      <c r="D4" t="inlineStr"><is><t>eligible</t></is></c>
      <c r="E4" t="inlineStr"><is><t>Dee Iron</t></is></c>
      <c r="F4" t="inlineStr"><is><t>FAKE-219346</t></is></c>
    </row>
  </sheetData>
</worksheet>"#;
