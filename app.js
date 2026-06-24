function $(id){ return document.getElementById(id); }
function escapeHtml(s){
  return (s ?? "").toString()
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}
function sevClass(sev){
  if(sev === "critical") return "sev-critical";
  if(sev === "high") return "sev-high";
  if(sev === "medium") return "sev-medium";
  return "sev-low";
}
function renderFindings(findings){
  const root = $("findings");
  if(!findings || findings.length === 0){
    root.innerHTML = `<div class="emptyState">No findings detected by current rules.</div>`;
    return;
  }
  root.innerHTML = findings.map(f => {
    const line = (f.line === null || f.line === undefined) ? "—" : f.line;
    return `
      <div class="finding">
        <div class="findingTop">
          <div class="findingTitle">${escapeHtml(f.title)}</div>
          <div class="meta">
            <span class="badge ${sevClass(f.severity)}">${escapeHtml(f.severity)}</span>
            <span class="badge">${escapeHtml(f.cwe)}</span>
            <span class="badge">Line ${escapeHtml(line)}</span>
          </div>
        </div>
        <div class="kv">
          <div class="k">Why</div>
          <div class="v"><pre>${escapeHtml(f.description)}</pre></div>
          <div class="k">Fix</div>
          <div class="v"><pre>${escapeHtml(f.fix)}</pre></div>
        </div>
      </div>
    `;
  }).join("");
}
function setStatus(text, kind){
  const el = $("status");
  el.className = "status" + (kind ? ` ${kind}` : "");
  el.textContent = text || "";
}
async function runAnalysis(){
  const code = $("code").value || "";
  const language = $("language").value || "python";
  setStatus("Analyzing…", "");
  $("analyzeBtn").disabled = true;
  try{
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ code, language })
    });
    const data = await res.json();
    $("riskScore").textContent = (data && data.risk_score !== undefined) ? data.risk_score : "0";
    renderFindings((data && data.findings) ? data.findings : []);
    setStatus(`Done. ${((data && data.findings) ? data.findings.length : 0)} finding(s).`, "ok");
  } catch(e){
    setStatus("Analysis failed. Check server logs.", "err");
  } finally {
    $("analyzeBtn").disabled = false;
  }
}
window.addEventListener("DOMContentLoaded", () => {
  $("analyzeBtn").addEventListener("click", runAnalysis);
});
