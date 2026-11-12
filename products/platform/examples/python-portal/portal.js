"use strict";

async function loadDashboard() {
  const element = document.getElementById("registry-dashboard");
  const initial = JSON.parse(element.textContent);
  if (initial !== null) {
    return initial;
  }
  const response = await fetch("/api/dashboard", {
    credentials: "same-origin",
    headers: {Accept: "application/json"},
  });
  if (!response.ok) {
    throw new Error("dashboard request failed");
  }
  return response.json();
}

loadDashboard()
  .then((value) => {
    document.getElementById("dashboard").textContent = JSON.stringify(value, null, 2);
  })
  .catch(() => {
    document.getElementById("dashboard").textContent = "Sign in again to continue.";
  });
