//! Writes JSON in Python's `json.dumps` layouts.

use std::io;

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, Serializer};

/// How a document is laid out, as the arguments of Python's `json.dumps` name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Spaces per level, or `None` for one line.
    pub indent: Option<usize>,
    /// `separators=(",", ":")`.
    pub compact_separators: bool,
    /// Every character outside printable ASCII written as `\uXXXX`.
    pub ensure_ascii: bool,
}

impl Style {
    /// `json.dumps(value)`.
    pub const LINE: Style = Style { indent: None, compact_separators: false, ensure_ascii: true };
    /// `json.dumps(value, indent=2)`.
    pub const INDENTED: Style = Style { indent: Some(2), compact_separators: false, ensure_ascii: true };
    /// `json.dumps(value, separators=(",", ":"))`.
    pub const COMPACT: Style = Style { indent: None, compact_separators: true, ensure_ascii: true };
    /// `json.dumps(value, ensure_ascii=False)`.
    pub const LINE_KEEPING_NON_ASCII: Style = Style { indent: None, compact_separators: false, ensure_ascii: false };
}

/// Write a value as JSON. Takes the value and the style. Returns the text, without a final newline.
pub fn to_string<T: Serialize + ?Sized>(value: &T, style: Style) -> Result<String, serde_json::Error> {
    let mut out = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut out, PythonFormatter::new(style));
    value.serialize(&mut serializer)?;
    Ok(String::from_utf8(out).expect("the writer writes UTF-8"))
}

/// Write a float as Python's `repr` writes it. Takes the float. Returns the text.
pub fn python_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0" } else { "0.0" }.to_string();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("{:e} writes an exponent");
    let exponent: i32 = exponent.parse().expect("{:e} writes a whole exponent");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.trim_start_matches('-').chars().filter(|c| *c != '.').collect();
    let body = if (-4..16).contains(&exponent) {
        fixed(&digits, exponent)
    } else {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        format!("{first}{fraction}e{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.abs())
    };
    if negative { format!("-{body}") } else { body }
}

fn fixed(digits: &str, exponent: i32) -> String {
    if exponent < 0 {
        return format!("0.{}{digits}", "0".repeat((-exponent - 1) as usize));
    }
    let whole = exponent as usize + 1;
    if digits.len() <= whole {
        format!("{digits}{}.0", "0".repeat(whole - digits.len()))
    } else {
        format!("{}.{}", &digits[..whole], &digits[whole..])
    }
}

struct PythonFormatter {
    style: Style,
    level: usize,
    has_value: bool,
}

impl PythonFormatter {
    fn new(style: Style) -> Self {
        PythonFormatter { style, level: 0, has_value: false }
    }

    fn item_separator(&self) -> &'static [u8] {
        if self.style.indent.is_some() || self.style.compact_separators { b"," } else { b", " }
    }

    fn newline<W: ?Sized + io::Write>(&self, writer: &mut W) -> io::Result<()> {
        if let Some(width) = self.style.indent {
            writer.write_all(b"\n")?;
            writer.write_all(" ".repeat(width * self.level).as_bytes())?;
        }
        Ok(())
    }

    fn open<W: ?Sized + io::Write>(&mut self, writer: &mut W, bracket: &[u8]) -> io::Result<()> {
        self.level += 1;
        self.has_value = false;
        writer.write_all(bracket)
    }

    fn close<W: ?Sized + io::Write>(&mut self, writer: &mut W, bracket: &[u8]) -> io::Result<()> {
        self.level -= 1;
        if self.has_value {
            self.newline(writer)?;
        }
        writer.write_all(bracket)
    }

    fn element<W: ?Sized + io::Write>(&mut self, writer: &mut W, first: bool) -> io::Result<()> {
        if !first {
            writer.write_all(self.item_separator())?;
        }
        self.newline(writer)
    }
}

impl Formatter for PythonFormatter {
    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        writer.write_all(python_float(value).as_bytes())
    }

    fn write_f32<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        self.write_f64(writer, f64::from(value))
    }

    fn write_string_fragment<W: ?Sized + io::Write>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()> {
        if !self.style.ensure_ascii {
            return writer.write_all(fragment.as_bytes());
        }
        let mut units = [0u16; 2];
        for character in fragment.chars() {
            if (' '..='~').contains(&character) {
                writer.write_all(character.encode_utf8(&mut [0; 4]).as_bytes())?;
            } else {
                for unit in character.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }

    fn write_char_escape<W: ?Sized + io::Write>(&mut self, writer: &mut W, escape: CharEscape) -> io::Result<()> {
        let text: &[u8] = match escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(byte) => return write!(writer, "\\u{byte:04x}"),
        };
        writer.write_all(text)
    }

    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.open(writer, b"[")
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.close(writer, b"]")
    }

    fn begin_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W, first: bool) -> io::Result<()> {
        self.element(writer, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, _writer: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.open(writer, b"{")
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.close(writer, b"}")
    }

    fn begin_object_key<W: ?Sized + io::Write>(&mut self, writer: &mut W, first: bool) -> io::Result<()> {
        self.element(writer, first)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(if self.style.compact_separators { b":" } else { b": " })
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, _writer: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }
}
