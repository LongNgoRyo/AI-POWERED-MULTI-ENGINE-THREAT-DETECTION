/**
 * MalwareGuardian AI - Client-side Interactive Logic
 */

let lastScanResult = null;

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initDropzone();
  initPathScanner();
  initSimulator();
  initCopyHash();
  initExportJson();
});

// ==========================================
// 1. Navigation Tabs
// ==========================================
function initTabs() {
  const tabBtns = document.querySelectorAll(".nav-tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");

      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
      }
    });
  });
}

// ==========================================
// 2. Drag & Drop & Upload
// ==========================================
function initDropzone() {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");

  if (!dropzone || !fileInput) return;

  dropzone.addEventListener("click", () => fileInput.click());

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      uploadFile(fileInput.files[0]);
    }
  });

  document.getElementById("btnScanAnother")?.addEventListener("click", () => {
    fileInput.value = "";
    document.getElementById("localFilePath").value = "";
    document.getElementById("scanPlaceholder").style.display = "block";
    document.getElementById("scanResultsContent").style.display = "none";
    document.getElementById("scanStatusBadge").textContent = "Chờ phân tích";
    document.getElementById("scanStatusBadge").className = "chip";
  });
}

async function uploadFile(file) {
  showScanningState(`Đang tải lên & phân tích: ${file.name}...`);
  
  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/scan-upload", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.error) {
      alert("Lỗi phân tích: " + data.error);
      resetScanningState();
    } else {
      renderScanResults(data);
    }
  } catch (err) {
    alert("Lỗi kết nối máy chủ: " + err.message);
    resetScanningState();
  }
}

// ==========================================
// 3. Local Machine Path Scanner & Presets
// ==========================================
function initPathScanner() {
  const btnScanPath = document.getElementById("btnScanPath");
  const inputPath = document.getElementById("localFilePath");

  const runScan = async () => {
    const path = inputPath.value.trim();
    if (!path) {
      alert("Vui lòng nhập đường dẫn file trên máy tính!");
      return;
    }
    showScanningState(`Đang quét file tại đường dẫn: ${path}...`);

    try {
      const res = await fetch("/api/scan-path", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: path })
      });
      const data = await res.json();
      if (data.error) {
        alert("Lỗi: " + data.error);
        resetScanningState();
      } else {
        renderScanResults(data);
      }
    } catch (err) {
      alert("Lỗi kết nối máy chủ: " + err.message);
      resetScanningState();
    }
  };

  btnScanPath?.addEventListener("click", runScan);
  inputPath?.addEventListener("keypress", (e) => {
    if (e.key === "Enter") runScan();
  });

  // Preset buttons
  document.querySelectorAll(".preset-btn[data-path]").forEach(btn => {
    btn.addEventListener("click", () => {
      const p = btn.getAttribute("data-path");
      inputPath.value = p;
      runScan();
    });
  });
}

function showScanningState(msg) {
  const badge = document.getElementById("scanStatusBadge");
  badge.textContent = "AI Đang Phân Tích...";
  badge.className = "chip";
  badge.style.borderColor = "var(--primary)";
  badge.style.color = "var(--primary)";

  const ph = document.getElementById("scanPlaceholder");
  ph.style.display = "block";
  ph.querySelector("h4").textContent = msg;
  document.getElementById("scanResultsContent").style.display = "none";
}

function resetScanningState() {
  const badge = document.getElementById("scanStatusBadge");
  badge.textContent = "Chờ phân tích";
  badge.className = "chip";
  document.getElementById("scanPlaceholder").style.display = "block";
  document.getElementById("scanResultsContent").style.display = "none";
}

// ==========================================
// 4. Render Scan Results
// ==========================================
function renderScanResults(data) {
  lastScanResult = data;

  document.getElementById("scanPlaceholder").style.display = "none";
  document.getElementById("scanResultsContent").style.display = "block";

  const badge = document.getElementById("scanStatusBadge");
  badge.textContent = "Hoàn tất";
  badge.style.borderColor = "var(--safe)";
  badge.style.color = "var(--safe)";

  // Verdict Banner
  const banner = document.getElementById("verdictBanner");
  const vTitle = document.getElementById("verdictTitle");
  const vIcon = document.getElementById("verdictIcon");
  const vEngine = document.getElementById("verdictEngine");
  const vScore = document.getElementById("verdictScore");

  banner.className = "verdict-banner";
  if (data.is_malicious) {
    banner.classList.add("danger");
    vTitle.textContent = data.risk_level.toUpperCase();
    vIcon.textContent = "☣️";
  } else {
    banner.classList.add("safe");
    vTitle.textContent = data.risk_level.toUpperCase();
    vIcon.textContent = "🛡️";
  }

  vEngine.textContent = `Động cơ: ${data.engine_used || "Generic Engine"}`;
  vScore.textContent = `${data.confidence_score}%`;

  // File Metadata
  document.getElementById("resFileName").textContent = data.file_name;
  document.getElementById("resFileSize").textContent = data.file_size_human;
  document.getElementById("resFileTypeBadge").textContent = data.detected_type;
  document.getElementById("resSha256").textContent = data.hashes.sha256;

  // Shannon Entropy
  const entVal = data.overall_entropy;
  document.getElementById("entropyVal").textContent = entVal.toFixed(2);
  const entPercent = Math.min(100, Math.max(0, (entVal / 8.0) * 100));
  const entFill = document.getElementById("entropyFill");
  entFill.style.width = `${entPercent}%`;

  const entStatus = document.getElementById("entropyStatus");
  if (entVal > 7.2) {
    entStatus.textContent = "Mức độ hỗn loạn rất cao (Nghi vấn Packer/Mã độc mã hóa)";
    entStatus.style.color = "var(--danger)";
  } else if (entVal > 6.0) {
    entStatus.textContent = "Mức độ hỗn loạn trung bình (Dữ liệu nén hoặc thư viện thông thường)";
    entStatus.style.color = "var(--warning)";
  } else {
    entStatus.textContent = "Bình thường (Dữ liệu không bị mã hóa/obfuscate)";
    entStatus.style.color = "var(--safe)";
  }

  // Feature Table
  const tbody = document.getElementById("featuresTableBody");
  tbody.innerHTML = "";

  let featureMap = {};
  if (data.details.pe_features) {
    featureMap = data.details.pe_features;
  } else if (data.details.pdf_features) {
    featureMap = data.details.pdf_features;
  } else {
    featureMap = {
      "Kích thước tệp (bytes)": data.file_size,
      "Độ hỗn loạn Entropy": data.overall_entropy,
      "Phần mở rộng": data.extension,
      "Mã băm MD5": data.hashes.md5,
      "Giả mạo đuôi (Spoofed)": data.spoofed_extension ? "CÓ NGUY HIỂM" : "KHÔNG"
    };
  }

  const keys = Object.keys(featureMap);
  document.getElementById("featuresCountBadge").textContent = `${keys.length} thuộc tính`;

  keys.forEach(k => {
    const tr = document.createElement("tr");
    const tdKey = document.createElement("td");
    const tdVal = document.createElement("td");

    tdKey.textContent = k;
    tdKey.style.color = "var(--text-muted)";

    const val = featureMap[k];
    tdVal.textContent = typeof val === "number" ? (Number.isInteger(val) ? val : val.toFixed(4)) : val;

    // Highlight suspicious values
    if (k === "SuspiciousSectionNames" && val > 0) {
      tdVal.style.color = "var(--danger)";
      tdVal.style.fontWeight = "700";
    } else if ((k === "/JavaScript" || k === "/JS" || k === "/OpenAction") && val > 0) {
      tdVal.style.color = "var(--warning)";
      tdVal.style.fontWeight = "700";
    }

    tr.appendChild(tdKey);
    tr.appendChild(tdVal);
    tbody.appendChild(tr);
  });
}

// ==========================================
// 5. Copy Hash & Export JSON
// ==========================================
function initCopyHash() {
  document.getElementById("btnCopyHash")?.addEventListener("click", () => {
    const hash = document.getElementById("resSha256").textContent;
    if (hash && hash !== "-") {
      navigator.clipboard.writeText(hash).then(() => {
        const btn = document.getElementById("btnCopyHash");
        btn.textContent = "✓ Đã Chép!";
        setTimeout(() => btn.textContent = "📋 Copy", 2000);
      });
    }
  });
}

function initExportJson() {
  document.getElementById("btnExportJson")?.addEventListener("click", () => {
    if (!lastScanResult) return;
    const blob = new Blob([JSON.stringify(lastScanResult, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `MalwareGuardian_Report_${lastScanResult.file_name}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// ==========================================
// 6. Process Behavior Simulator (100k Model)
// ==========================================
function initSimulator() {
  const form = document.getElementById("simForm");
  if (!form) return;

  // Presets
  document.getElementById("btnPresetBenignProc")?.addEventListener("click", (e) => {
    e.preventDefault();
    document.getElementById("sim_total_vm").value = "150";
    document.getElementById("sim_exec_vm").value = "124";
    document.getElementById("sim_shared_vm").value = "120";
    document.getElementById("sim_map_count").value = "6850";
    document.getElementById("sim_nvcsw").value = "341974";
    document.getElementById("sim_min_flt").value = "0";
    document.getElementById("sim_maj_flt").value = "120";
    document.getElementById("sim_utime").value = "380690";
    document.getElementById("sim_prio").value = "3069378560";
  });

  document.getElementById("btnPresetMalProc")?.addEventListener("click", (e) => {
    e.preventDefault();
    // Typical ransomware / rootkit process memory behavior values from 100k dataset
    document.getElementById("sim_total_vm").value = "85";
    document.getElementById("sim_exec_vm").value = "120";
    document.getElementById("sim_shared_vm").value = "112";
    document.getElementById("sim_map_count").value = "2150";
    document.getElementById("sim_nvcsw").value = "1250";
    document.getElementById("sim_min_flt").value = "240";
    document.getElementById("sim_maj_flt").value = "450";
    document.getElementById("sim_utime").value = "98200";
    document.getElementById("sim_prio").value = "3069378560";
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      total_vm: parseFloat(document.getElementById("sim_total_vm").value) || 0,
      exec_vm: parseFloat(document.getElementById("sim_exec_vm").value) || 0,
      shared_vm: parseFloat(document.getElementById("sim_shared_vm").value) || 0,
      map_count: parseFloat(document.getElementById("sim_map_count").value) || 0,
      nvcsw: parseFloat(document.getElementById("sim_nvcsw").value) || 0,
      min_flt: parseFloat(document.getElementById("sim_min_flt").value) || 0,
      maj_flt: parseFloat(document.getElementById("sim_maj_flt").value) || 0,
      utime: parseFloat(document.getElementById("sim_utime").value) || 0,
      prio: parseFloat(document.getElementById("sim_prio").value) || 0
    };

    try {
      const res = await fetch("/api/simulate-behavior", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      
      const title = document.getElementById("simVerdictTitle");
      const icon = document.getElementById("simIcon");
      const desc = document.getElementById("simDesc");
      const prob = document.getElementById("simProb");

      if (data.is_malicious) {
        title.textContent = "PHÁT HIỆN MÃ ĐỘC TIẾN TRÌNH";
        title.style.color = "var(--danger)";
        icon.textContent = "☣️";
        desc.textContent = "Mô hình LightGBM xác nhận các chỉ số phân đoạn bộ nhớ ảo và chuyển đổi ngữ cảnh mang dấu hiệu mã độc cao.";
      } else {
        title.textContent = "TIẾN TRÌNH LÀNH TÍNH";
        title.style.color = "var(--safe)";
        icon.textContent = "🛡️";
        desc.textContent = "Mô hình xác nhận các chỉ số cấp phát bộ nhớ ảo và chuyển đổi ngữ cảnh phù hợp với tiến trình phần mềm hợp pháp.";
      }
      prob.textContent = `${data.confidence_score}%`;
    } catch (err) {
      alert("Lỗi khi mô phỏng: " + err.message);
    }
  });
}

// ==========================================
// 7. Image Modal Enlargement
// ==========================================
function openImageModal(src) {
  const modal = document.getElementById("imgModal");
  const modalImg = document.getElementById("modalImg");
  if (modal && modalImg) {
    modalImg.src = src;
    modal.classList.add("active");
  }
}

function closeImageModal() {
  const modal = document.getElementById("imgModal");
  if (modal) {
    modal.classList.remove("active");
  }
}
