
chrome.downloads.onChanged.addListener(delta => {
  if (!delta.state || delta.state.current !== "complete") return;

  chrome.downloads.search({ id: delta.id }, items => {
    if (!items || !items[0] || !items[0].filename) return;

    fetch("http://127.0.0.1:5000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filepath: items[0].filename })
    })
    .then(r => r.json())
    .then(d => {
      // store result for popup
      chrome.storage.local.set({ lastResult: d }, () => {

        // 🔔 automatically open extension popup
        if (chrome.action && chrome.action.openPopup) {
          chrome.action.openPopup();
        } else {
          chrome.windows.create({
            url: "popup.html",
            type: "popup",
            width: 400,
            height: 500
          });
        }

      });
    })
    .catch(err => {
      console.error("B-MADS scan error:", err);
    });
  });
});
