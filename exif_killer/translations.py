"""Small translation layer for the desktop GUI."""

from __future__ import annotations

CURRENT_LANG = "en"

TRANSLATIONS = {
    "en": {
        "title": "Exif Killer",
        "subtitle": "Offline metadata sanitizer + verifier",
        "drop_title": "Drop files or folders here",
        "drop_hint": "Supported: JPG, PNG, WEBP, BMP, TIFF, PDF, DOCX, XLSX, PPTX",
        "add_files": "Add Files",
        "add_folder": "Add Folder",
        "scan": "Scan",
        "clean": "Clean + Verify",
        "clear": "Clear",
        "export": "Export Report",
        "settings": "Settings",
        "profile": "Profile",
        "safe": "Safe",
        "aggressive": "Aggressive",
        "file_queue": "Queued Files",
        "details": "Details",
        "terminal": "Terminal",
        "status_ready": "Ready",
        "output_mode": "Output Mode",
        "queue_count": "Queue Count",
        "same_folder_mode": "Same folder",
        "overwrite_mode": "Overwrite originals",
        "custom_output_mode": "Custom folder",
        "no_files": "No files queued.",
        "no_details": "Scan or clean files to view structured findings.",
        "files_added": "Queued {count} supported file(s).",
        "unsupported_skipped": "Skipped {count} unsupported input(s).",
        "scan_started": "Metadata scan started.",
        "clean_started": "Cleaning and verification started.",
        "busy": "Background task is already running.",
        "nothing_to_scan": "Add files before scanning.",
        "nothing_to_clean": "Add files before cleaning.",
        "batch_summary": "Summary: clean={clean} warning={warning} error={error} unsupported={unsupported}",
        "settings_title": "Output Settings",
        "output_dir": "Output directory",
        "same_as_source": "Same as source folder",
        "choose_folder": "Choose Folder",
        "select_folder_to_queue": "Select Folder to Queue",
        "overwrite": "Overwrite original files",
        "save": "Save",
        "cancel": "Cancel",
        "language": "Language",
        "report_saved": "Report written to {path}",
        "report_failed": "Could not export report: {error}",
        "no_report": "Run scan or clean first to export a report.",
        "processing": "Processing {current}/{total}: {name}",
        "complete": "Complete",
        "overview": "Overview",
        "warnings": "Warnings",
        "findings": "Findings",
        "removed_fields": "Removed fields",
        "remaining_findings": "Remaining findings",
        "metadata_fields": "Metadata fields",
        "hash_before": "SHA256 before",
        "hash_after": "SHA256 after",
        "output_path": "Output path",
        "status": "Status",
        "type": "Type",
        "profile_label": "Profile",
    },
    "tr": {
        "title": "Exif Killer",
        "subtitle": "Cevrimdisi metadata temizleyici + dogrulayici",
        "drop_title": "Dosya veya klasorleri buraya birak",
        "drop_hint": "Desteklenen: JPG, PNG, WEBP, BMP, TIFF, PDF, DOCX, XLSX, PPTX",
        "add_files": "Dosya Ekle",
        "add_folder": "Klasor Ekle",
        "scan": "Tara",
        "clean": "Temizle + Dogrula",
        "clear": "Temizle",
        "export": "Raporu Disari Aktar",
        "settings": "Ayarlar",
        "profile": "Profil",
        "safe": "Guvenli",
        "aggressive": "Agresif",
        "file_queue": "Siradaki Dosyalar",
        "details": "Detaylar",
        "terminal": "Terminal",
        "status_ready": "Hazir",
        "output_mode": "Cikti Modu",
        "queue_count": "Kuyruk Sayisi",
        "same_folder_mode": "Ayni klasor",
        "overwrite_mode": "Orijinalleri ez",
        "custom_output_mode": "Ozel klasor",
        "no_files": "Sirada dosya yok.",
        "no_details": "Yapilandirilmis bulgular icin once tara veya temizle.",
        "files_added": "{count} desteklenen dosya siraya alindi.",
        "unsupported_skipped": "{count} desteklenmeyen girdi atlandi.",
        "scan_started": "Metadata taramasi basladi.",
        "clean_started": "Temizleme ve dogrulama basladi.",
        "busy": "Arka planda zaten bir islem calisiyor.",
        "nothing_to_scan": "Taramadan once dosya ekle.",
        "nothing_to_clean": "Temizlemeden once dosya ekle.",
        "batch_summary": "Ozet: temiz={clean} uyari={warning} hata={error} desteklenmeyen={unsupported}",
        "settings_title": "Cikti Ayarlari",
        "output_dir": "Cikti klasoru",
        "same_as_source": "Kaynak klasor ile ayni",
        "choose_folder": "Klasor Sec",
        "select_folder_to_queue": "Kuyruga Eklenecek Klasoru Sec",
        "overwrite": "Orijinal dosyalarin uzerine yaz",
        "save": "Kaydet",
        "cancel": "Iptal",
        "language": "Dil",
        "report_saved": "Rapor yazildi: {path}",
        "report_failed": "Rapor disa aktarilamadi: {error}",
        "no_report": "Rapor disa aktarmadan once tara veya temizle.",
        "processing": "Isleniyor {current}/{total}: {name}",
        "complete": "Tamamlandi",
        "overview": "Genel Bakis",
        "warnings": "Uyarilar",
        "findings": "Bulgular",
        "removed_fields": "Silinen alanlar",
        "remaining_findings": "Kalan bulgular",
        "metadata_fields": "Metadata alanlari",
        "hash_before": "SHA256 once",
        "hash_after": "SHA256 sonra",
        "output_path": "Cikti yolu",
        "status": "Durum",
        "type": "Tur",
        "profile_label": "Profil",
    },
}


def get_text(key: str, lang: str | None = None) -> str:
    """Return a translated text value."""
    language = lang or CURRENT_LANG
    return TRANSLATIONS.get(language, TRANSLATIONS["en"]).get(
        key,
        TRANSLATIONS["en"].get(key, key),
    )


def set_language(lang: str) -> None:
    """Set the current language."""
    global CURRENT_LANG
    if lang in TRANSLATIONS:
        CURRENT_LANG = lang


def get_current_language() -> str:
    """Get the active language code."""
    return CURRENT_LANG


def toggle_language() -> str:
    """Toggle between English and Turkish."""
    global CURRENT_LANG
    CURRENT_LANG = "tr" if CURRENT_LANG == "en" else "en"
    return CURRENT_LANG
