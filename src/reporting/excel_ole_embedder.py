"""Embed files into Excel worksheets as OLE objects (Windows + Excel)."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

_logger = logging.getLogger(__name__)

# Excel 97-2003 workbook — required to persist OLE package objects.
_XL_EXCEL8 = 56


def embed_file_in_worksheet(
    workbook_path: Path,
    sheet_name: str,
    file_path: Path,
    *,
    left: float = 24,
    top: float = 110,
    width: float = 520,
    height: float = 360,
) -> Path | None:
    """Embed *file_path* into *sheet_name* of a saved Excel workbook.

    Returns the path of the workbook that contains the OLE object, or None on
    failure.  Open XML (``.xlsx``) cannot persist OLE packages, so when needed
    the workbook is re-saved as ``.xls`` (Excel 97-2003) and the original
    ``.xlsx`` is removed.

    Requires Windows with Excel + pywin32 installed.
    """
    if sys.platform != "win32":
        _logger.info("OLE embedding skipped — supported on Windows only")
        return None

    workbook_path = Path(workbook_path)
    file_path = Path(file_path)
    if not workbook_path.exists():
        _logger.warning("Workbook not found for OLE embed: %s", workbook_path)
        return None
    if not file_path.exists():
        _logger.warning("File not found for OLE embed: %s", file_path)
        return None

    try:
        import win32com.client  # type: ignore[import-untyped]
    except ImportError:
        _logger.warning("pywin32 not available — cannot embed OLE object")
        return None

    excel = None
    workbook = None
    final_path: Path | None = None
    try:
        excel = win32com.client.DispatchEx("Excel.Application")
        excel.Visible = False
        excel.DisplayAlerts = False

        workbook = excel.Workbooks.Open(str(workbook_path.resolve()))
        worksheet = workbook.Worksheets(sheet_name)
        # Positional args required — named kwargs fail with win32com (HRESULT 0x800A17AC).
        # DisplayAsIcon=True embeds ZIP/PDF/DOC as clickable package icons.
        worksheet.OLEObjects().Add(
            None,
            str(file_path.resolve()),
            False,
            True,
            None,
            0,
            None,
            left,
            top,
            width,
            height,
        )
        try:
            workbook.Save()
            final_path = workbook_path
        except Exception as save_exc:
            # .xlsx cannot store OLE; fall back to binary .xls.
            _logger.info(
                "Save after OLE failed on %s (%s); re-saving as .xls",
                workbook_path,
                save_exc,
            )
            xls_path = workbook_path.with_suffix(".xls")
            workbook.SaveAs(str(xls_path.resolve()), FileFormat=_XL_EXCEL8)
            final_path = xls_path
            workbook.Close(SaveChanges=False)
            workbook = None
            if workbook_path != xls_path and workbook_path.exists():
                try:
                    workbook_path.unlink()
                except OSError:
                    pass
        return final_path
    except Exception as exc:
        _logger.exception("Failed to embed OLE object in %s: %s", workbook_path, exc)
        try:
            from core.process_logger import get_process_logger

            plog = get_process_logger()
            if plog is not None:
                plog.fail(
                    "OLE embed",
                    f"workbook={Path(workbook_path).name}; file={Path(file_path).name}",
                    exc=exc,
                )
        except Exception:
            pass
        return None
    finally:
        if workbook is not None:
            try:
                workbook.Close(SaveChanges=False)
            except Exception:
                pass
        if excel is not None:
            try:
                excel.Quit()
            except Exception:
                pass
