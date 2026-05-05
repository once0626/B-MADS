document.addEventListener("DOMContentLoaded", () => {

  // Toggle only if element exists
  document.querySelectorAll(".toggle").forEach(el => {
    el.addEventListener("click", () => {
      const targetId = el.dataset.target;
      const target = document.getElementById(targetId);
      const arrow = el.querySelector(".arrow");

      if (!target) return;

      const isOpen = target.style.display === "block";
      target.style.display = isOpen ? "none" : "block";

      if (arrow) {
        arrow.style.transform = isOpen ? "rotate(0deg)" : "rotate(90deg)";
      }
    });
  });

  // Load last scan result safely
  chrome.storage.local.get("lastResult", data => {
    const d = data.lastResult;
    if (!d) return;

    // Verdict
    const verdictEl = document.getElementById("verdict");

if (verdictEl) {

  const verdict = d.analysis?.verdict || d.verdict || "Unknown";
  const filename = d.metadata?.filename || "file";

  const verdictText = `The file ${filename} is ${verdict.toUpperCase()}`;

  verdictEl.innerText = verdictText;

  verdictEl.classList.add(verdict.toLowerCase());
}

    // Reasons (always visible)
    const reasonsEl = document.getElementById("reasons");
    if (reasonsEl) {
      reasonsEl.innerHTML = "";
      const reasons =
        d.analysis?.static_reasons ||
        d.analysis?.details ||
        d.reasons ||
        ["No suspicious indicators detected"];

      reasons.forEach(r => {
        const li = document.createElement("li");
        li.innerText = r;
        reasonsEl.appendChild(li);
      });
    }

    // Technical details
    const techEl = document.getElementById("techDetails");
    if (techEl) {
      techEl.innerText = JSON.stringify(d, null, 2);
    }
  });
});
