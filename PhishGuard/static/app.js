document.querySelectorAll(".scan-form").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type='submit']");
    const input = form.querySelector("[name='content']");
    const original = button.innerHTML;
    const content = input.value.trim();
    if (!content) return;
    button.disabled = true;
    button.innerHTML = "Analyzing <span class='spinner'></span>";
    try {
      const response = await fetch("/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({scan_type: form.dataset.scanType, content})
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Unable to analyze this input.");
      showResult(result, form.dataset.scanType);
      window.location.reloadAfterResult = true;
    } catch (error) {
      alert(error.message);
    } finally {
      button.disabled = false;
      button.innerHTML = original;
    }
  });
});

function showResult(result, type) {
  const modal = document.getElementById("result-modal");
  const content = document.getElementById("result-content");
  const levelClass = result.level.toLowerCase();
  const indicators = result.indicators.map(item => `
    <div class="result-indicator">
      <span class="indicator-check">${item.points ? "!" : "✓"}</span>
      <div><strong>${escapeHtml(item.label)}</strong><p>${escapeHtml(item.explanation)}</p></div>
      <span class="points">${item.points ? "+" + item.points : "0"}</span>
    </div>`).join("");
  const advice = result.recommendations.map(item => `<li>${escapeHtml(item)}</li>`).join("");
  content.innerHTML = `
    <div class="result-kicker">${type === "url" ? "URL ANALYSIS" : "EMAIL ANALYSIS"} COMPLETE</div>
    <h2 id="result-title">Risk assessment</h2>
    <p class="result-subtitle">Review the indicators below to understand the assessment.</p>
    <div class="score-area">
      <div class="score-ring ${levelClass}"><div><strong>${result.score}</strong><small>/ 100</small></div></div>
      <div><span class="risk-badge ${levelClass}">${escapeHtml(result.level)} RISK</span><h3>${result.level === "Safe" ? "No obvious warning signs" : result.level === "Low" ? "A few signs to review" : result.level === "Medium" ? "Use additional caution" : result.level === "High" ? "Suspicious content detected" : "Highly suspicious content"}</h3><p>Rule-based estimate only — not a guarantee.</p></div>
    </div>
    <h3 class="result-section-title">Detected indicators</h3>
    <div class="result-indicators">${indicators}</div>
    <h3 class="result-section-title">Recommended actions</h3>
    <ul class="recommendation-list">${advice}</ul>
    <button class="primary-btn result-done" data-close="true">Done <span>✓</span></button>`;
  modal.classList.remove("hidden");
  modal.querySelectorAll("[data-close='true']").forEach(el => el.addEventListener("click", closeModal));
}
function closeModal() {
  const modal = document.getElementById("result-modal");
  modal.classList.add("hidden");
  if (window.location.reloadAfterResult) window.location.reload();
}
document.querySelectorAll("[data-close='true']").forEach(el => el.addEventListener("click", closeModal));
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[char]);
}
