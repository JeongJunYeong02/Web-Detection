// popup.js (수정된 최종본)

// ===============================
// 📋 DOMContentLoaded 이벤트 (웹페이지 분석)
// ===============================
document.addEventListener('DOMContentLoaded', function() {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const statusText = document.getElementById('statusText');
  const resultsDiv = document.getElementById('results');

  const riskScoreEl = document.getElementById('riskScore');
  const riskLevelEl = document.getElementById('riskLevel');
  const textSimEl = document.getElementById('textSimilarity');
  const domSimEl = document.getElementById('domSimilarity');
  const semanticSimEl = document.getElementById('semanticSimilarity');
  const urlSimEl = document.getElementById('urlSimilarity');
  const iframeCountEl = document.getElementById('iframeCount');
  const warningsList = document.getElementById('warningsList');
  const iframeWarningsDiv = document.getElementById('iframeWarnings');
  const iframeWarningsList = document.getElementById('iframeWarningsList');
  const linkWarningsDiv = document.getElementById('linkWarnings');
  const linkWarningsList = document.getElementById('linkWarningsList');
  const internalLinkSummaryEl = document.getElementById('internalLinkSummary');

  function toPct(v){
    if (typeof v !== 'number' || Number.isNaN(v)) return '-';
    return (v * 100).toFixed(1) + '%';
  }

  function pick(){
    for (let i = 0; i < arguments.length; i++) {
      const v = arguments[i];
      if (v !== undefined && v !== null) return v;
    }
    return undefined;
  }

  // 🔸 (웹 분석) 현재 탭의 HTML을 가져와 Flask 서버로 전송
  analyzeBtn.addEventListener('click', async function() {
    statusText.textContent = '페이지 분석 중...';
    analyzeBtn.disabled = true;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tab.url || !tab.url.startsWith('http')) {
        throw new Error('http:// 또는 https:// 페이지만 분석할 수 있습니다.');
      }

      const injectionResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => document.documentElement.outerHTML,
      });

      if (!injectionResults || !injectionResults[0] || !injectionResults[0].result) {
        throw new Error('페이지 HTML을 가져오지 못했습니다.');
      }
      const pageHTML = injectionResults[0].result;

      const serverUrl = 'http://127.0.0.1:5050/check_current_page';
      const response = await fetch(serverUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ html: pageHTML, url: tab.url }),
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`서버 응답 오류: ${response.status} (${errText})`);
      }

      const data = await response.json();
      displayResults(data);

    } catch (error) {
      console.error('분석 중 오류:', error);
      if (error.message.includes('Failed to fetch')) {
        statusText.textContent = '❌ 서버 연결 실패! (5050 포트)';
      } else {
        statusText.textContent = '오류 발생: ' + error.message;
      }
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  // 🔸 (웹 분석) 결과 표시 함수
  function displayResults(data) {
    try {
      resultsDiv.style.display = 'block';
      const risk = data.risk_assessment || {};
      const scores = data.scores || data.metrics || {};
      if (riskScoreEl) riskScoreEl.textContent = pick(risk.risk_score, '-') + '';
      if (riskLevelEl) {
        const level = (pick(risk.risk_level, '-') + '').toUpperCase();
        riskLevelEl.textContent = level;
        riskLevelEl.className = 'risk-level risk-' + (pick(risk.risk_level, 'unknown'));
      }
      if (statusText) statusText.textContent = pick(risk.risk_message, '분석 완료');
      if (textSimEl) textSimEl.textContent = toPct(pick(data.text_similarity?.cosine_similarity, scores.text));
      if (domSimEl) domSimEl.textContent = toPct(pick(data.dom_similarity?.tree_edit_distance, scores.dom));
      if (semanticSimEl) semanticSimEl.textContent = (pick(data.semantic_similarity, scores.semantic) === 1.0) ? '100.0%' : '-';
      if (urlSimEl) urlSimEl.textContent = toPct(pick(data.url_similarity?.url_levenshtein, scores.url));
      if (iframeCountEl) iframeCountEl.textContent = (pick(data.iframe_analysis?.suspicious_iframes?.length, 0) ?? '-') + '개';
      if(internalLinkSummaryEl && data.internal_links) {
          internalLinkSummaryEl.textContent = `${data.internal_links.suspicious_links?.length || 0} / ${data.internal_links.total_links || 0} 개 경고`
      }
      warningsList.innerHTML = '';
      const warnings = pick(risk.warnings, data.warnings, []);
      if (Array.isArray(warnings) && warnings.length > 0) {
        warnings.forEach(warning => {
          const li = document.createElement('li');
          li.textContent = typeof warning === 'string' ? warning : JSON.stringify(warning);
          warningsList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = '경고 사항 없음';
        li.style.color = '#4caf50';
        warningsList.appendChild(li);
      }
      const iframeWarn = data.iframe_analysis?.suspicious_iframes || [];
      if (Array.isArray(iframeWarn) && iframeWarn.length > 0) {
        iframeWarningsDiv.style.display = 'block';
        iframeWarningsList.innerHTML = '';
        iframeWarn.forEach(warningObject => {
          const li = document.createElement('li');
          let text = `[${warningObject.index}번 iframe] ${warningObject.warnings?.join(', ') || '의심'}`;
          if (warningObject.src) text += ` (src: ${warningObject.src.substring(0, 50)}...)`;
          li.textContent = text;
          li.style.whiteSpace = 'pre-wrap';
          iframeWarningsList.appendChild(li);
        });
      } else {
        iframeWarningsDiv.style.display = 'none';
      }
      const linkWarn = data.internal_links?.suspicious_links || [];
        if (Array.isArray(linkWarn) && linkWarn.length > 0) {
            linkWarningsDiv.style.display = 'block';
            linkWarningsList.innerHTML = '';
            linkWarn.forEach(linkObject => {
                const li = document.createElement('li');
                li.textContent = `[${linkObject.reason || '의심'}] ${linkObject.text || ''} (url: ${linkObject.url.substring(0, 50)}...)`;
                linkWarningsList.appendChild(li);
            });
        } else {
            linkWarningsDiv.style.display = 'none';
        }
    } catch (e) {
      console.error('displayResults error:', e);
      statusText.textContent = '결과 렌더링 중 오류: ' + e.message;
    }
  }
});

// ===============================
// 🧠 이미지 유사도 분석 버튼 (★ 수정됨)
// ===============================
document.getElementById("imgAnalyzeBtn").addEventListener("click", async () => {
  const imgResult = document.getElementById("imgResult");
  const imgAnalyzeBtn = document.getElementById("imgAnalyzeBtn");
  
  imgResult.textContent = "현재 탭 스냅샷 찍는 중...";
  imgAnalyzeBtn.disabled = true;

  try {
    // 1. (셀레니움 대신) Chrome API로 현재 탭 스냅샷 찍기
    const dataUrl = await chrome.tabs.captureVisibleTab(null, {
      format: "png" // PNG 형식으로 캡처
    });
    
    imgResult.textContent = "스냅샷 전송 및 분석 중... (AutoEncoder)";

    // 2. 서버로 {베이스라인 경로, 스냅샷 Base64} 전송
    const response = await fetch("http://127.0.0.1:5050/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        // (1) 베이스라인 이미지 (서버 경로)
        img1_path: "images/class1/1.png", 
        // (2) 방금 찍은 스냅샷 (Base64 데이터)
        img2_data: dataUrl
      })
    });

    if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || "서버 응답 오류");
    }

    const result = await response.json();
    const finalScore = result.final.toFixed(2);
    const status = finalScore >= 70 ? "✅ 안전!" : "⚠️ 위험!";
    imgResult.textContent = `${status}\n최종 결합 유사도: ${finalScore}%`;

  } catch (err) {
    console.error("이미지 분석 오류:", err);
    imgResult.textContent = "❌ 분석 실패: " + err.message;
    if (err.message.includes('Failed to fetch')) {
        imgResult.textContent += "\n(5050 서버가 켜있는지 확인하세요)";
    }
  } finally {
      imgAnalyzeBtn.disabled = false;
  }
});