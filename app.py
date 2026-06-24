from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from sentrix.core.analyzer import analyze

app = Flask(
    __name__,
    template_folder="sentrix/templates",
    static_folder="sentrix/static",
)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze_route():
    payload = request.get_json(silent=True) or {}
    code = payload.get("code", "") or ""
    language = payload.get("language", "python") or "python"

    result = analyze(code=code, language=language)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5050"))
    app.run(host="127.0.0.1", port=port, debug=True)

