// manuals.js

// index.html 존재 확인
async function existsHtml(sw, ver) {
  const url = `/manuals/api/html_meta?sw=${encodeURIComponent(sw)}&version=${encodeURIComponent(ver)}`;
  try {
    const r = await fetch(url, { cache: "no-store" });
    return r.ok;
  } catch {
    return false;
  }
}

// 실제 열기
async function openManual(sw, ver) {
  const ok = await existsHtml(sw, ver);
  const frame = document.getElementById("manualFrame");
  const holder = document.getElementById("placeholder");
  const wrap = document.getElementById("viewerWrap");
  const label = document.getElementById("current-label");
  const pdfBtn = document.getElementById("pdfBtn");

  if (!ok) {
    // 실패: 뷰어 숨김 + 안내
    wrap.style.display = "none";
    holder.style.display = "flex";
    label.textContent = `버전: ${ver} / SW: ${sw} (index.html 없음)`;
    pdfBtn.disabled = true;
    pdfBtn.onclick = null;
    alert(`index.html 없음:\n/uploads/manuals/${sw}/${ver}/index.html`);
    return;
  }

  // iframe 로드
  const src = `/manuals_static/${encodeURIComponent(sw)}/${encodeURIComponent(ver)}/index.html`;
  frame.src = src;

  holder.style.display = "none";
  wrap.style.display = "block";
  label.textContent = `버전: ${ver} / SW: ${sw}`;

  // PDF “버튼” 동작(링크 아님)
  pdfBtn.disabled = false;
  pdfBtn.onclick = () => {
    const pdfUrl = `/manuals/export/pdf?sw=${encodeURIComponent(sw)}&version=${encodeURIComponent(ver)}`;
    // 새 탭/창으로 다운로드
    window.open(pdfUrl, "_blank", "noopener,noreferrer");
  };
}

// 좌측 SW 버튼 하이라이트
function highlight(sw) {
  document.querySelectorAll(".sw-btn").forEach(btn => {
    if (btn.dataset.sw === sw) {
      btn.classList.add("ring-2", "ring-blue-500");
    } else {
      btn.classList.remove("ring-2", "ring-blue-500");
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const verSel = document.getElementById("ver-select");
  const label = document.getElementById("current-label");

  // 초기 라벨
  if (verSel && label) {
    label.textContent = `버전: ${verSel.value}`;
  }

  // 버전 변경 시 현재 선택 SW가 있으면 재로딩
  verSel.addEventListener("change", () => {
    const active = document.querySelector(".sw-btn.ring-2");
    if (active) {
      const sw = active.dataset.sw;
      openManual(sw, verSel.value);
      highlight(sw);
    } else {
      // SW 미선택 상태: 라벨만 갱신
      label.textContent = `버전: ${verSel.value}`;
    }
  });

  // SW 버튼 클릭 바인딩
  document.querySelectorAll(".sw-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const sw = btn.dataset.sw;
      const ver = verSel.value;
      highlight(sw);
      openManual(sw, ver);
    });
  });
});
