console.log('위변조 탐지 확장프로그램 로드됨');

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === 'analyzePage') {
    analyzePage().then(data => {
      sendResponse({ success: true, data: data });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }
});

async function analyzePage() {
  const html = document.documentElement.outerHTML;
  const url = window.location.href;
  
  const snapshot = {
    url: url,
    html: html,
    title: document.title,
    domain: window.location.hostname,
    iframes: extractIframes(),
    links: extractLinks(),
    forms: extractForms(),
    timestamp: new Date().toISOString()
  };

  try {
    const response = await fetch('http://localhost:5010/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(snapshot)
    });

    if (!response.ok) {
      throw new Error('서버 응답 오류');
    }

    const result = await response.json();
    
    if (result.iframe_analysis.suspicious_iframes.length > 0) {
      highlightSuspiciousIframes(result.iframe_analysis.suspicious_iframes);
    }
    
    return result;
    
  } catch (error) {
    console.error('분석 오류:', error);
    return performBasicAnalysis(snapshot);
  }
}

function extractIframes() {
  const iframes = document.querySelectorAll('iframe');
  return Array.from(iframes).map((iframe, index) => ({
    index: index,
    src: iframe.src || '',
    width: iframe.width || '',
    height: iframe.height || '',
    style: iframe.getAttribute('style') || ''
  }));
}

function extractLinks() {
  const links = document.querySelectorAll('a[href]');
  return Array.from(links).slice(0, 50).map(link => ({
    href: link.href,
    text: link.textContent.trim().substring(0, 50)
  }));
}

function extractForms() {
  const forms = document.querySelectorAll('form');
  return Array.from(forms).map(form => ({
    action: form.action || '',
    method: form.method || 'get',
    hasPasswordInput: form.querySelector('input[type="password"]') !== null
  }));
}

function highlightSuspiciousIframes(suspiciousIframes) {
  const iframes = document.querySelectorAll('iframe');
  
  suspiciousIframes.forEach(susIframe => {
    const iframe = iframes[susIframe.index];
    if (iframe) {
      iframe.style.border = '5px solid red';
      iframe.style.outline = '5px solid red';
      
      const overlay = document.createElement('div');
      overlay.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        background-color: rgba(255, 0, 0, 0.9);
        color: white;
        padding: 10px;
        font-size: 14px;
        font-weight: bold;
        z-index: 999999;
        cursor: not-allowed;
      `;
      overlay.textContent = '⚠️ 경고: 화이트리스트에 없는 iframe! 클릭하지 마세요!';
      
      const container = document.createElement('div');
      container.style.position = 'relative';
      container.style.display = 'inline-block';
      
      iframe.parentNode.insertBefore(container, iframe);
      container.appendChild(iframe);
      container.appendChild(overlay);
    }
  });
}

function performBasicAnalysis(snapshot) {
  const suspiciousIframes = snapshot.iframes.filter(iframe => {
    const trustedDomains = ['youtube.com', 'google.com', 'naver.com'];
    try {
      const iframeDomain = new URL(iframe.src || 'about:blank').hostname;
      return !trustedDomains.some(domain => iframeDomain.includes(domain));
    } catch {
      return true;
    }
  });

  return {
    text_similarity: { cosine_similarity: 1.0 },
    dom_similarity: { tree_edit_distance: 1.0 },
    iframe_analysis: {
      total_iframes: snapshot.iframes.length,
      suspicious_iframes: suspiciousIframes,
      risk_level: suspiciousIframes.length > 0 ? 'medium' : 'low'
    },
    risk_assessment: {
      risk_score: suspiciousIframes.length * 20,
      risk_level: suspiciousIframes.length > 2 ? 'high' : 
                 suspiciousIframes.length > 0 ? 'medium' : 'low',
      risk_message: suspiciousIframes.length > 0 ? 
        '⚠️ 화이트리스트에 없는 iframe이 발견되었습니다.' : 
        '✅ 의심스러운 요소가 발견되지 않았습니다.',
      warnings: suspiciousIframes.length > 0 ? 
        [`${suspiciousIframes.length}개의 화이트리스트에 없는 iframe 발견`] : [],
      iframe_warnings: suspiciousIframes.map(iframe => 
        `iframe #${iframe.index}: ${iframe.src.substring(0, 50)}...`
      )
    }
  };
}