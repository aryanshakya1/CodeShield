/* CodeShield - Interactive Cryptography Client Script */

// Helper to trigger file download in browser
function downloadFile(filename, content, mimeType = "text/plain") {
  const blob = (content instanceof Blob) ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Convert base64 to Blob
function base64ToBlob(base64, mimeType = "application/octet-stream") {
  const byteCharacters = atob(base64);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  return new Blob([byteArray], { type: mimeType });
}

// -------------------------------------------------------------
// MODULE 1: SIGNING PAGE HANDLERS
// -------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  // Key Generation
  const btnGenKeys = document.getElementById("btn-generate-keys");
  if (btnGenKeys) {
    btnGenKeys.addEventListener("click", async () => {
      const password = document.getElementById("key-password").value;
      const keyGenStatus = document.getElementById("keygen-status");
      const keyResultArea = document.getElementById("keygen-results");

      btnGenKeys.disabled = true;
      btnGenKeys.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Generating RSA 2048-bit Keys...`;
      if (keyGenStatus) keyGenStatus.classList.remove("d-none");

      try {
        const response = await fetch("/api/generate-keys", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: password })
        });
        const data = await response.json();

        if (data.success) {
          // Display keys
          document.getElementById("priv-key-display").value = data.private_key;
          document.getElementById("pub-key-display").value = data.public_key;
          document.getElementById("keygen-time").textContent = `${data.generation_time_ms} ms`;
          keyResultArea.classList.remove("d-none");

          // Wire up download buttons
          document.getElementById("btn-dl-priv").onclick = () => {
            downloadFile("private_key.pem", data.private_key, "application/x-pem-file");
          };
          document.getElementById("btn-dl-pub").onclick = () => {
            downloadFile("public_key.pem", data.public_key, "application/x-pem-file");
          };

          // Auto-fill into the signing form below to make it ultra convenient
          const privKeyText = document.getElementById("sign-privkey-text");
          if (privKeyText) privKeyText.value = data.private_key;
          const signPass = document.getElementById("sign-password");
          if (signPass && password) signPass.value = password;

        } else {
          alert("Key Generation Error: " + data.error);
        }
      } catch (err) {
        alert("Request failed: " + err.message);
      } finally {
        btnGenKeys.disabled = false;
        btnGenKeys.innerHTML = `<i class="bi bi-key-fill me-2"></i>Generate RSA Keys`;
      }
    });
  }

  // File Signing Form
  const formSign = document.getElementById("form-sign-file");
  if (formSign) {
    formSign.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btnSign = document.getElementById("btn-sign-submit");
      const signResults = document.getElementById("sign-results");
      const signAlert = document.getElementById("sign-error-alert");

      if (signAlert) signAlert.classList.add("d-none");

      const formData = new FormData(formSign);

      btnSign.disabled = true;
      btnSign.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Signing File...`;

      try {
        const res = await fetch("/api/sign-file", {
          method: "POST",
          body: formData
        });
        const data = await res.json();

        if (data.success) {
          document.getElementById("res-sign-filename").textContent = data.filename;
          document.getElementById("res-sign-filesize").textContent = `${data.file_size} bytes`;
          document.getElementById("res-sign-hash").textContent = data.sha256_hash;
          document.getElementById("res-sign-time").textContent = `${data.signing_time_ms} ms`;
          document.getElementById("res-hash-time").textContent = `${data.hashing_time_ms} ms`;
          document.getElementById("res-sign-sigpreview").textContent = data.signature_hex;

          // Wire Download .sig button
          const btnDlSig = document.getElementById("btn-download-sig");
          btnDlSig.onclick = () => {
            const sigBlob = base64ToBlob(data.signature_base64, "application/octet-stream");
            const sigName = `${data.filename}.sig`;
            downloadFile(sigName, sigBlob);
          };

          signResults.classList.remove("d-none");
          signResults.scrollIntoView({ behavior: "smooth" });
        } else {
          if (signAlert) {
            signAlert.textContent = data.error || "An error occurred during signing.";
            signAlert.classList.remove("d-none");
          } else {
            alert("Signing Error: " + data.error);
          }
        }
      } catch (err) {
        alert("Network or server error: " + err.message);
      } finally {
        btnSign.disabled = false;
        btnSign.innerHTML = `<i class="bi bi-pen-fill me-2"></i>Sign File`;
      }
    });
  }

  // -------------------------------------------------------------
  // MODULE 2: VERIFICATION PAGE HANDLERS
  // -------------------------------------------------------------
  const formVerify = document.getElementById("form-verify-file");
  if (formVerify) {
    formVerify.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btnVerify = document.getElementById("btn-verify-submit");
      const verifyResultCard = document.getElementById("verify-result-card");
      const verifyAlert = document.getElementById("verify-error-alert");

      if (verifyAlert) verifyAlert.classList.add("d-none");

      const formData = new FormData(formVerify);

      btnVerify.disabled = true;
      btnVerify.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Verifying Integrity...`;

      try {
        const res = await fetch("/api/verify-signature", {
          method: "POST",
          body: formData
        });
        const data = await res.json();

        if (data.success) {
          const banner = document.getElementById("verify-status-banner");
          const title = document.getElementById("verify-status-title");
          const icon = document.getElementById("verify-status-icon");

          if (data.valid) {
            banner.className = "result-banner-valid mb-4";
            title.textContent = "Signature Valid — File Integrity Verified";
            icon.className = "bi bi-shield-check display-4 text-success me-3";
          } else {
            banner.className = "result-banner-invalid mb-4";
            title.textContent = "Signature Invalid — File May Have Been Modified";
            icon.className = "bi bi-shield-x display-4 text-danger me-3";
          }

          document.getElementById("verify-explanation").textContent = data.explanation;
          document.getElementById("verify-hash").textContent = data.sha256_hash;
          document.getElementById("verify-time").textContent = `${data.verification_time_ms} ms`;
          document.getElementById("verify-filename").textContent = data.filename;

          verifyResultCard.classList.remove("d-none");
          verifyResultCard.scrollIntoView({ behavior: "smooth" });
        } else {
          if (verifyAlert) {
            verifyAlert.textContent = data.error || "An error occurred during verification.";
            verifyAlert.classList.remove("d-none");
          } else {
            alert("Verification Error: " + data.error);
          }
        }
      } catch (err) {
        alert("Network or server error: " + err.message);
      } finally {
        btnVerify.disabled = false;
        btnVerify.innerHTML = `<i class="bi bi-shield-check me-2"></i>Verify Signature`;
      }
    });
  }

  // -------------------------------------------------------------
  // MODULE 3: SECURITY TESTING HANDLERS
  // -------------------------------------------------------------
  const btnRunTamperTest = document.getElementById("btn-test-tampering");
  const btnRunWrongKeyTest = document.getElementById("btn-test-wrongkey");
  const btnRunAllTests = document.getElementById("btn-test-all");

  async function executeSecurityTest(testType) {
    const loadingElem = document.getElementById("security-test-loading");
    const container = document.getElementById("security-results-container");

    if (loadingElem) loadingElem.classList.remove("d-none");

    try {
      const res = await fetch("/api/security-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_type: testType })
      });
      const data = await res.json();

      if (data.success) {
        const results = data.results;

        // Render Tampering details if present
        const tamperSection = document.getElementById("sec-tamper-details");
        if (results.tampering_test && tamperSection) {
          tamperSection.classList.remove("d-none");
          const origCodeElem = document.getElementById("tamper-orig-code");
          const modCodeElem = document.getElementById("tamper-mod-code");
          if (origCodeElem) origCodeElem.value = results.tampering_test.original_code;
          if (modCodeElem) modCodeElem.value = results.tampering_test.tampered_code;

          document.getElementById("tamper-orig-hash").textContent = results.tampering_test.original_hash;
          document.getElementById("tamper-mod-hash").textContent = results.tampering_test.tampered_hash;
          document.getElementById("tamper-explanation").textContent = results.tampering_test.explanation;

          const badge = document.getElementById("tamper-status-badge");
          if (badge) {
            if (results.tampering_test.valid) {
              badge.className = "badge bg-success px-3 py-2 fs-6 fw-bold shadow";
              badge.textContent = "Verification PASSED";
            } else {
              badge.className = "badge bg-danger px-3 py-2 fs-6 fw-bold shadow";
              badge.textContent = "Verification FAILED (Tampering Detected)";
            }
          }
        }

        // Render Wrong Key details if present
        const wrongKeySection = document.getElementById("sec-wrongkey-details");
        if (results.wrong_key_test && wrongKeySection) {
          wrongKeySection.classList.remove("d-none");
          document.getElementById("key-a-preview").textContent = results.wrong_key_test.key_a_preview;
          document.getElementById("key-b-preview").textContent = results.wrong_key_test.key_b_preview;
          document.getElementById("wrongkey-file-hash").textContent = results.wrong_key_test.file_hash;
          document.getElementById("wrongkey-explanation").textContent = results.wrong_key_test.explanation;
        }

        // Render Table Summary with explicit high-contrast inline styling
        const tableBody = document.getElementById("security-summary-body");
        if (tableBody && results.summary_table) {
          tableBody.innerHTML = "";
          results.summary_table.forEach(item => {
            const badgeClass = item.result === "Valid" ? "bg-success" : "bg-danger";
            const icon = item.result === "Valid" ? "bi-check-circle-fill" : "bi-x-circle-fill";
            const row = document.createElement("tr");
            row.style.backgroundColor = "#09101f";
            row.innerHTML = `
              <td class="fw-bold py-3 ps-3" style="color: #ffffff !important; background-color: #09101f !important; font-size: 1.05rem; vertical-align: middle;">
                <i class="bi bi-shield-check text-info me-2"></i>${item.test}
              </td>
              <td class="text-center py-3 pe-3" style="background-color: #09101f !important; vertical-align: middle;">
                <span class="badge ${badgeClass} px-3 py-2 fs-6 fw-bold shadow" style="font-size: 0.95rem !important;">
                  <i class="bi ${icon} me-1"></i>
                  ${item.result}
                </span>
              </td>
            `;
            tableBody.appendChild(row);
          });
        }

        if (container) container.classList.remove("d-none");
      } else {
        alert("Security test error: " + data.error);
      }
    } catch (err) {
      alert("Failed to execute security test: " + err.message);
    } finally {
      if (loadingElem) loadingElem.classList.add("d-none");
    }
  }

  // Interactive Tamper Lab Event Listeners
  const btnVerifyCustom = document.getElementById("btn-verify-tamper-custom");
  if (btnVerifyCustom) {
    btnVerifyCustom.addEventListener("click", async () => {
      const origCode = document.getElementById("tamper-orig-code").value;
      const modCode = document.getElementById("tamper-mod-code").value;
      const loadingElem = document.getElementById("security-test-loading");

      if (loadingElem) loadingElem.classList.remove("d-none");
      btnVerifyCustom.disabled = true;

      try {
        const res = await fetch("/api/security-test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            test_type: "tampering",
            original_code: origCode,
            tampered_code: modCode
          })
        });
        const data = await res.json();
        if (data.success && data.results.tampering_test) {
          const t = data.results.tampering_test;
          document.getElementById("tamper-orig-hash").textContent = t.original_hash;
          document.getElementById("tamper-mod-hash").textContent = t.tampered_hash;
          document.getElementById("tamper-explanation").textContent = t.explanation;

          const badge = document.getElementById("tamper-status-badge");
          if (badge) {
            if (t.valid) {
              badge.className = "badge bg-success px-3 py-2 fs-6 fw-bold shadow";
              badge.textContent = "Verification PASSED (Unmodified)";
            } else {
              badge.className = "badge bg-danger px-3 py-2 fs-6 fw-bold shadow";
              badge.textContent = "Verification FAILED (Tampering Detected)";
            }
          }
        }
      } catch (err) {
        alert("Verification error: " + err.message);
      } finally {
        if (loadingElem) loadingElem.classList.add("d-none");
        btnVerifyCustom.disabled = false;
      }
    });
  }

  if (btnRunTamperTest) {
    btnRunTamperTest.addEventListener("click", () => executeSecurityTest("tampering"));
  }
  if (btnRunWrongKeyTest) {
    btnRunWrongKeyTest.addEventListener("click", () => executeSecurityTest("wrong_key"));
  }
  if (btnRunAllTests) {
    btnRunAllTests.addEventListener("click", () => executeSecurityTest("all"));
  }

  // -------------------------------------------------------------
  // MODULE 4: PERFORMANCE BENCHMARK HANDLERS
  // -------------------------------------------------------------
  const btnRunBenchmark = document.getElementById("btn-run-benchmark");
  if (btnRunBenchmark) {
    btnRunBenchmark.addEventListener("click", async () => {
      const benchmarkContainer = document.getElementById("benchmark-results");
      const loading = document.getElementById("benchmark-loading");

      btnRunBenchmark.disabled = true;
      if (loading) loading.classList.remove("d-none");

      try {
        const res = await fetch("/api/performance-benchmark", { method: "POST" });
        const data = await res.json();

        if (data.success) {
          const m = data.metrics;
          document.getElementById("metric-keygen").textContent = `${m.key_gen_ms} ms`;
          document.getElementById("metric-hash").textContent = `${m.hash_ms} ms`;
          document.getElementById("metric-sign").textContent = `${m.sign_ms} ms`;
          document.getElementById("metric-verify").textContent = `${m.verify_ms} ms`;

          // Startup Overhead
          document.getElementById("metric-normal-startup").textContent = `${m.avg_normal_ms} ms`;
          document.getElementById("metric-verified-startup").textContent = `${m.avg_verified_ms} ms`;
          document.getElementById("metric-overhead-ms").textContent = `+${m.avg_overhead_ms} ms (${m.overhead_percent}%)`;

          // Chart
          const chartImg = document.getElementById("performance-chart-img");
          if (chartImg && data.chart_base64) {
            chartImg.src = `data:image/png;base64,${data.chart_base64}`;
          }

          if (benchmarkContainer) {
            benchmarkContainer.classList.remove("d-none");
            benchmarkContainer.scrollIntoView({ behavior: "smooth" });
          }
        } else {
          alert("Benchmark error: " + data.error);
        }
      } catch (err) {
        alert("Failed to run benchmark: " + err.message);
      } finally {
        btnRunBenchmark.disabled = false;
        if (loading) loading.classList.add("d-none");
      }
    });
  }
});
