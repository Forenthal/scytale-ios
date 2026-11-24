//! PDF rendering through the engine built into Windows (Windows.Data.Pdf), maintained and patched
//! by Windows Update. The document is handed over from memory, so no plaintext touches the disk.
//! The input stream and each rendered page's buffer are overwritten with zeros when done.

use image::ImageFormat;
use windows::{
    core::Interface,
    Data::Pdf::{PdfDocument, PdfPageRenderOptions},
    Foundation::IAsyncOperation,
    Storage::Streams::{DataReader, DataWriter, InMemoryRandomAccessStream},
    Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED},
};
use zeroize::Zeroizing;

use crate::gui::Pixels;

/// Largest rendered page, in pixels.
const MAX_PIXELS: u64 = 40_000_000;

pub fn init() {
    // SAFETY: once per thread, before any WinRT call.
    unsafe {
        let _ = RoInitialize(RO_INIT_MULTITHREADED);
    }
}

fn we(e: windows::core::Error) -> String {
    format!("Windows PDF engine error 0x{:08x}", e.code().0 as u32)
}

fn write_all(s: &InMemoryRandomAccessStream, data: &[u8]) -> Result<(), String> {
    let w = DataWriter::CreateDataWriter(s).map_err(we)?;
    w.WriteBytes(data).map_err(we)?;
    w.StoreAsync().map_err(we)?.cast::<IAsyncOperation<u32>>().map_err(we)?.get().map_err(we)?;
    w.DetachStream().map_err(we)?;
    Ok(())
}

fn read_all(s: &InMemoryRandomAccessStream, n: u32) -> Result<Zeroizing<Vec<u8>>, String> {
    s.Seek(0).map_err(we)?;
    let r = DataReader::CreateDataReader(s).map_err(we)?;
    r.LoadAsync(n).map_err(we)?.cast::<IAsyncOperation<u32>>().map_err(we)?.get().map_err(we)?;
    let mut v = Zeroizing::new(vec![0u8; n as usize]);
    r.ReadBytes(&mut v).map_err(we)?;
    r.DetachStream().map_err(we)?;
    Ok(v)
}

/// Overwrite a stream's contents in place with zeros.
fn wipe(s: &InMemoryRandomAccessStream, n: u32) {
    if s.Seek(0).is_ok() {
        let _ = write_all(s, &vec![0u8; n as usize]);
    }
}

pub struct Pdf {
    doc: Option<PdfDocument>,
    input: InMemoryRandomAccessStream,
    len: u32,
    pub pages: u32,
}

impl Pdf {
    pub fn open(data: &[u8]) -> Result<Pdf, String> {
        let len = u32::try_from(data.len()).map_err(|_| "PDF too large".to_string())?;
        let input = InMemoryRandomAccessStream::new().map_err(we)?;
        let mut pdf = Pdf { doc: None, input, len, pages: 0 };
        write_all(&pdf.input, data)?;
        pdf.input.Seek(0).map_err(we)?;
        let doc = PdfDocument::LoadFromStreamAsync(&pdf.input).map_err(we)?.get().map_err(|e| {
            if e.code().0 as u32 == 0x8007_052B {
                "the PDF is password-protected (not supported)".to_string()
            } else {
                format!("not a readable PDF ({})", we(e))
            }
        })?;
        pdf.pages = doc.PageCount().map_err(we)?;
        pdf.doc = Some(doc);
        if pdf.pages == 0 {
            return Err("the PDF has no pages".into());
        }
        Ok(pdf)
    }

    /// Render one page at `width` pixels wide.
    pub fn render(&self, index: u32, width: u32) -> Result<Pixels, String> {
        let doc = self.doc.as_ref().ok_or("document closed")?;
        let page = doc.GetPage(index).map_err(we)?;
        let size = page.Size().map_err(we)?;
        if !(size.Width > 0.0 && size.Height > 0.0) {
            return Err("page has no size".into());
        }
        let mut w = width.max(1);
        let mut h = ((w as f32 * size.Height / size.Width).round() as u32).max(1);
        while w as u64 * h as u64 > MAX_PIXELS {
            w = w * 3 / 4;
            h = h * 3 / 4;
        }
        let opts = PdfPageRenderOptions::new().map_err(we)?;
        opts.SetDestinationWidth(w).map_err(we)?;
        opts.SetDestinationHeight(h).map_err(we)?;
        let out = InMemoryRandomAccessStream::new().map_err(we)?;
        page.RenderWithOptionsToStreamAsync(&out, &opts).map_err(we)?.get().map_err(we)?;
        let _ = page.Close();
        let n = u32::try_from(out.Size().map_err(we)?).map_err(|_| "page too large".to_string())?;
        let png = read_all(&out, n);
        wipe(&out, n);
        let _ = out.Close();
        let png = png?;
        let img = image::load_from_memory_with_format(&png, ImageFormat::Png).map_err(|_| "could not decode the rendered page".to_string())?;
        let rgba = img.into_rgba8();
        let (iw, ih) = rgba.dimensions();
        Ok(Pixels::from_rgba(iw, ih, rgba.into_raw()))
    }
}

impl Drop for Pdf {
    fn drop(&mut self) {
        if let Some(d) = self.doc.take() {
            drop(d);
        }
        wipe(&self.input, self.len);
        let _ = self.input.Close();
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A minimal valid one-page PDF: a red rectangle on a white page.
    pub fn sample_pdf() -> Vec<u8> {
        let content = "1 0 0 rg 50 50 100 60 re f";
        let objs = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << >> >>".to_string(),
            format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()),
        ];
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offs = Vec::new();
        for (i, o) in objs.iter().enumerate() {
            offs.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
        }
        let xref = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
        for o in offs {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
        out
    }

    #[test]
    fn renders_a_page_from_memory() {
        init();
        let pdf = Pdf::open(&sample_pdf()).unwrap();
        assert_eq!(pdf.pages, 1);
        let p = pdf.render(0, 400).unwrap();
        assert_eq!(p.w, 400);
        assert_eq!(p.h, 400);
        // PDF y grows upwards: the rectangle (x 50..150, y 50..110 in points) is near the bottom-left.
        let at = |x: u32, y: u32| {
            let i = ((y * p.w + x) * 4) as usize;
            (p.bgra[i + 2], p.bgra[i + 1], p.bgra[i])
        };
        // at 2 px/pt the rectangle covers x 100..300 and y 180..300 (top-down)
        assert_eq!(at(200, 240), (255, 0, 0), "inside the red rectangle");
        assert_eq!(at(380, 20), (255, 255, 255), "white page background");
        assert!(Pdf::open(b"not a pdf at all").is_err());
    }
}
