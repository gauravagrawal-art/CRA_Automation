// The only JavaScript in this UI: poll a running job, and confirm actions that
// start a scan or freeze a baseline. No compliance logic runs in the browser.

(function () {
  "use strict";

  document.addEventListener("submit", function (event) {
    var form = event.target;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
      return;
    }
    var button = form.querySelector('button[type="submit"]:not([data-no-busy])');
    if (button) {
      // Left enabled so the value still posts; disabling would drop it.
      button.setAttribute("aria-busy", "true");
      button.textContent = button.getAttribute("data-busy-label") || "Working…";
    }
  });

  var panel = document.getElementById("job-panel");
  if (!panel) return;

  var url = panel.getAttribute("data-poll");
  var redirect = panel.getAttribute("data-redirect") || "/";
  if (!url) return;

  function poll() {
    fetch(url, { headers: { "X-Requested-With": "fetch" } })
      .then(function (response) {
        if (!response.ok) throw new Error("poll failed");
        return response.text();
      })
      .then(function (html) {
        panel.innerHTML = html;
        var state = panel.querySelector("[data-status]");
        var status = state ? state.getAttribute("data-status") : "RUNNING";
        if (status === "SUCCEEDED") {
          // The job refines its own redirect as it learns the run ID.
          window.location.replace(state.getAttribute("data-redirect") || redirect);
        } else if (status === "RUNNING") {
          window.setTimeout(poll, 1500);
        }
      })
      .catch(function () {
        window.setTimeout(poll, 4000);
      });
  }

  window.setTimeout(poll, 900);
})();
