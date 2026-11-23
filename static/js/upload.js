/* static/js/upload.js — Drag & drop file upload with XHR progress & TSF extraction polling */

(function () {
  document.addEventListener("DOMContentLoaded", () => {
    const dropzone = document.getElementById("fw-dropzone");
    const fileInput = document.getElementById("fw-file-input");
    const browseBtn = document.getElementById("fw-browse-btn");
    const progressWrap = document.getElementById("fw-upload-progress");
    const progressText = document.getElementById("fw-progress-text");
    const progressBar = document.getElementById("fw-progress-bar");
    const errorBox = document.getElementById("fw-upload-error");

    if (!dropzone || !fileInput) return;

    function showError(msg) {
      if (!errorBox) return;
      errorBox.textContent = msg;
      errorBox.style.display = "block";
    }

    function clearError() {
      if (!errorBox) return;
      errorBox.textContent = "";
      errorBox.style.display = "none";
    }

    function setProgress(pct, label) {
      if (!progressWrap) return;
      progressWrap.style.display = "block";
      if (progressText) progressText.textContent = label;
      if (progressBar) progressBar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
    }

    function hideProgress() {
      if (progressWrap) progressWrap.style.display = "none";
    }

    function pollTsfJob(jobId) {
      const poll = () => {
        fetch(`/api/tsf/progress/${encodeURIComponent(jobId)}`)
          .then((r) => r.json())
          .then((data) => {
            if (data.status === "error") {
              hideProgress();
              showError(`TSF extraction failed: ${data.error || "Unknown error"}`);
              return;
            }
            const pct = Math.round((data.progress || 0) * 100);
            setProgress(pct, data.message || "Extracting TSF archive...");
            if (data.status === "done") {
              setProgress(100, `Extracted ${data.total_files || 0} files. Opening TSF Explorer...`);
              window.location.href = "/tsf";
              return;
            }
            setTimeout(poll, 350);
          })
          .catch((err) => {
            hideProgress();
            showError(`Lost connection while checking extraction progress: ${err.message}`);
          });
      };
      poll();
    }

    function uploadFile(file) {
      if (!file) return;
      clearError();

      const fd = new FormData();
      fd.append("file", file);

      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload", true);

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          setProgress(pct, `Uploading ${file.name} (${pct}%)...`);
        } else {
          setProgress(30, `Uploading ${file.name}...`);
        }
      };

      xhr.upload.onload = () => {
        setProgress(100, `Parsing ${file.name}...`);
      };

      xhr.onload = () => {
        let data = {};
        try {
          data = JSON.parse(xhr.responseText || "{}");
        } catch (_) {}

        if (xhr.status >= 200 && xhr.status < 300) {
          if (data.type === "tsf" && data.job_id) {
            setProgress(5, "TSF package detected. Preparing analysis environment...");
            pollTsfJob(data.job_id);
          } else if (data.redirect) {
            window.location.href = data.redirect;
          } else {
            window.location.href = "/workspace";
          }
        } else {
          hideProgress();
          showError(data.detail || `Upload failed (HTTP ${xhr.status}).`);
        }
      };

      xhr.onerror = () => {
        hideProgress();
        showError("Network error while uploading file.");
      };

      setProgress(2, `Preparing ${file.name}...`);
      xhr.send(fd);
    }

    if (browseBtn) {
      browseBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        fileInput.click();
      });
    }

    dropzone.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) {
        uploadFile(fileInput.files[0]);
        fileInput.value = "";
      }
    });

    ["dragenter", "dragover"].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove("dragover");
      });
    });

    dropzone.addEventListener("drop", (e) => {
      const files = e.dataTransfer && e.dataTransfer.files;
      if (files && files[0]) {
        uploadFile(files[0]);
      }
    });
  });
})();
