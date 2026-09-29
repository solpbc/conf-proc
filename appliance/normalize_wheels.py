"""Remove installer provenance that depends on workspace paths or wall-clock time."""
import csv
import io
from pathlib import Path
import shutil


def normalize(target: Path) -> None:
    # These trees are import-only; generated console scripts carry host shebangs.
    shutil.rmtree(target / "bin", ignore_errors=True)
    for metadata in sorted(target.glob("*.dist-info")):
        removed = {"direct_url.json", "uv_cache.json"}
        for name in removed:
            (metadata / name).unlink(missing_ok=True)
        record = metadata / "RECORD"
        if not record.exists():
            continue
        rows = list(csv.reader(io.StringIO(record.read_text())))
        rows = [row for row in rows if not (
            row[0] in {f"{metadata.name}/{name}" for name in removed}
            or row[0].startswith(("bin/", "../bin/", "../../bin/")))]
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(sorted(rows))
        record.unlink()  # callers may have staged inputs using hardlinks
        record.write_text(output.getvalue())
