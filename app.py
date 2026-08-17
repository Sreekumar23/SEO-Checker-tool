import csv
import io
import traceback
from pathlib import Path

from flask import Flask, render_template, request, send_file, jsonify, Response

from footer_audit import FooterAudit, generate_excel_report, generate_comparison_excel

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

BASE_DIR = Path(__file__).resolve().parent
URLS_PATH = BASE_DIR / "urls.txt"
OUTPUT_PATH = BASE_DIR / "footer_report.csv"
COMPARISON_PATH = BASE_DIR / "comparison_report.csv"
README_PATH = BASE_DIR / "README.md"


@app.route("/", methods=["GET"])
def index():
    report_exists = OUTPUT_PATH.exists()
    resp = app.make_response(render_template("index.html", report_exists=report_exists))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/audit-single", methods=["POST"])
def audit_single():
    url = request.json.get("url", "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    # analyze_url() directly — do NOT call run() so the batch footer_report.csv
    # is never overwritten by a single-URL check.
    audit_runner = FooterAudit(str(URLS_PATH), str(OUTPUT_PATH))
    row = audit_runner.analyze_url(url)
    return jsonify({"status": "success", "results": [row]})


@app.route("/api/audit-batch", methods=["POST"])
def audit_batch():
    urls_text = request.json.get("urls", "")
    audit_type = request.json.get("audit_type", "both")
    urls = [line.strip() for line in urls_text.splitlines() if line.strip()]
    if not urls:
        return jsonify({"error": "Please enter at least one URL."}), 400

    URLS_PATH.write_text("\n".join(urls) + "\n", encoding="utf-8")
    audit_runner = FooterAudit(str(URLS_PATH), str(OUTPUT_PATH))
    rows = audit_runner.run(audit_type=audit_type)
    if rows:
        return jsonify({"status": "success", "results": rows})
    return jsonify({"error": "No results."}), 500


@app.route("/api/audit-comparison", methods=["POST"])
def audit_comparison():
    urls_text = request.json.get("urls", "")
    urls = [line.strip() for line in urls_text.splitlines() if line.strip()]
    if not urls:
        return jsonify({"error": "Please enter at least one URL."}), 400

    audit_runner = FooterAudit(str(URLS_PATH), str(OUTPUT_PATH))
    results = []
    comparison = []

    for url in urls:
        local = audit_runner.analyze_url(url)
        results.append(local)

        canonical = FooterAudit.derive_canonical_url(url)
        if canonical:
            en = audit_runner.analyze_url(canonical)
        else:
            en = local  # Already English — compare against itself

        local_failed = bool(local.get("note", "").startswith("Fetch failed"))
        en_failed = bool(en.get("note", "").startswith("Fetch failed"))

        comparison.append({
            "local_url":  url,
            "english_url": canonical or url,
            "language":   local.get("language", "English"),
            "product":    local.get("product", ""),
            "already_english": canonical is None,
            "local_load_error": local_failed,
            "local_error_msg":  local.get("note", "") if local_failed else "",
            "en_load_error": en_failed,
            "en_error_msg":  en.get("note", "") if en_failed else "",
            # LHS
            "local_lhs_detected": local.get("lhs_detected", False),
            "local_lhs_links":    local.get("lhs_link_count", 0),
            "local_lhs_sections": local.get("lhs_sections", ""),
            "local_lhs_related":  local.get("lhs_related_products", False),
            "en_lhs_detected": en.get("lhs_detected", False),
            "en_lhs_links":    en.get("lhs_link_count", 0),
            "en_lhs_sections": en.get("lhs_sections", ""),
            "en_lhs_related":  en.get("lhs_related_products", False),
            # RHS
            "local_rhs_detected": local.get("rhs_detected", False),
            "local_rhs_links":    local.get("rhs_link_count", 0),
            "local_rhs_sections": local.get("rhs_sections", ""),
            "en_rhs_detected": en.get("rhs_detected", False),
            "en_rhs_links":    en.get("rhs_link_count", 0),
            "en_rhs_sections": en.get("rhs_sections", ""),
            # Footer
            "local_footer_detected": local.get("footer_detected", False),
            "local_footer_tabs":     local.get("detected_tabs", ""),
            "en_footer_detected": en.get("footer_detected", False),
            "en_footer_tabs":     en.get("detected_tabs", ""),
            # CTA
            "local_cta_detected": local.get("cta_detected", False),
            "local_cta_pattern":  local.get("cta_pattern", ""),
            "local_cta_text":     local.get("cta_text", ""),
            "en_cta_detected": en.get("cta_detected", False),
            "en_cta_pattern":  en.get("cta_pattern", ""),
            "en_cta_text":     en.get("cta_text", ""),
        })

    audit_runner.write_comparison_report(comparison, COMPARISON_PATH)
    # Also write main results to footer_report.csv so the Download CSV/Excel
    # buttons (which point to /download and /download-excel) serve the current
    # audit's data — comparison mode routes here instead of /api/audit-batch,
    # so without this write the download always serves a stale file.
    audit_type = request.json.get("audit_type", "both")
    audit_runner.write_report(results, audit_type=audit_type)
    return jsonify({"status": "success", "results": results, "comparison": comparison})


@app.route("/download")
def download():
    if not OUTPUT_PATH.exists():
        return "No report available yet.", 404
    return send_file(OUTPUT_PATH, as_attachment=True, download_name="footer_report.csv")


@app.route("/download-comparison")
def download_comparison():
    if not COMPARISON_PATH.exists():
        return "No comparison report available yet.", 404
    return send_file(COMPARISON_PATH, as_attachment=True, download_name="comparison_report.csv")


@app.route("/download-excel")
def download_excel():
    if not OUTPUT_PATH.exists():
        return "No report available yet.", 404
    try:
        with OUTPUT_PATH.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            rows = list(reader)
        wb = generate_excel_report(rows, fieldnames)
        buf = io.BytesIO()
        wb.save(buf)
        data = buf.getvalue()
        return Response(
            data,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=footer_report.xlsx"},
        )
    except Exception as e:
        app.logger.error("download_excel failed: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/api/download-comparison-excel", methods=["POST"])
def download_comparison_excel():
    rows = request.json.get("rows", [])
    if not rows:
        return jsonify({"error": "No data."}), 400
    try:
        wb = generate_comparison_excel(rows)
        buf = io.BytesIO()
        wb.save(buf)
        data = buf.getvalue()
        return Response(
            data,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=comparison_report.xlsx"},
        )
    except Exception as e:
        app.logger.error("download_comparison_excel failed: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/download-readme")
def download_readme():
    if not README_PATH.exists():
        return "README not found.", 404
    return send_file(README_PATH, as_attachment=True, download_name="README.md")


@app.route("/version")
def version():
    from footer_audit import PRODUCT_URL_MAP
    products = [name for _, name, _, _ in PRODUCT_URL_MAP]
    return jsonify({"products": products, "version": "cloud-siem-added"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=True)
