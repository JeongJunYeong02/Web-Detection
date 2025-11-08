"""
웹사이트 위변조 탐지 시스템 (CodeBERT 제외 버전)
- 텍스트 유사도
- DOM 구조 비교
- URL 유사도 (로그인 폼 분석 포함)
- 내부 링크 URL 추출 및 검사 (고도화)
- iframe 화이트리스트 검사 (CSV 기반)
"""

from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from zss import simple_distance, Node
from urllib.parse import urlparse, urljoin
import numpy as np
import re
import Levenshtein
import pandas as pd
from pathlib import Path

# --- CodeBERT (제거됨) ---
_HAS_CODEBERT = False

class WebForgeryDetector:
    """웹사이트 위변조 종합 탐지 시스템"""
    
    # ★ [수정] __init__ 생성자에서 baseline_url 기본값을 수정
    def __init__(self, whitelist_csv_path, baseline_html=None, baseline_html_path=None, baseline_url="http://localhost:8000/normal.html#"):  # type: ignore
        """
        Args:
            whitelist_csv_path: 화이트리스트 URL이 담긴 CSV 파일 경로
            baseline_html: 코드 내에서 직접 지정된 baseline HTML (옵션)
            baseline_html_path: 파일에서 baseline HTML을 읽어올 경로 (옵션)
            baseline_url: baseline HTML의 기본 URL (도메인 유사도 비교용)
        """
        self.whitelist_urls = set()
        self.whitelist_domains = set()
        
        if whitelist_csv_path:
            self.load_whitelist_from_csv(whitelist_csv_path)

        self.baseline_url = baseline_url
        self.baseline_html = None
        if baseline_html:
            self.baseline_html = baseline_html
        else:
            try:
                # __file__ (현재 파일) 기준으로 baseline_html_path 탐색
                path = Path(baseline_html_path) if baseline_html_path else (Path(__file__).parent / "normal.html")
                if path.exists():
                    self.baseline_html = path.read_text(encoding="utf-8")
                    print(f"✅ Baseline HTML loaded from: {path}")
                else:
                    print(f"❌ [WARN] Baseline HTML not found at: {path}")
            except Exception as e:
                print(f"❌ Failed to load baseline HTML: {e}")
    
    def load_whitelist_from_csv(self, csv_path):
        try:
            df = pd.read_csv(csv_path)
            if 'url' in df.columns:
                urls = df['url'].dropna()
            elif 'domain' in df.columns:
                self.whitelist_domains.update(df['domain'].dropna().astype(str).str.strip())
                urls = [] # 도메인만 로드
            else:
                urls = df.iloc[:, 0].dropna() # 첫 번째 열
            
            for url in urls:
                url = str(url).strip()
                self.whitelist_urls.add(url)
                domain = self._extract_domain(url)
                if domain:
                    self.whitelist_domains.add(domain)
            
            print(f"✅ 화이트리스트 로드 완료: {len(self.whitelist_urls)} URLs, {len(self.whitelist_domains)} domains")
        
        except FileNotFoundError:
            print(f"❌ CSV 파일을 찾을 수 없습니다: {csv_path}")
        except Exception as e:
            print(f"❌ CSV 로드 중 오류 발생: {e}")
    
    def is_url_whitelisted(self, url):
        if not url:
            return {'is_whitelisted': False, 'match_type': 'empty', 'matched_entry': None}
        url = url.strip()
        if url in self.whitelist_urls:
            return {'is_whitelisted': True, 'match_type': 'exact_url', 'matched_entry': url}
        domain = self._extract_domain(url)
        if domain:
            if domain in self.whitelist_domains:
                return {'is_whitelisted': True, 'match_type': 'exact_domain', 'matched_entry': domain}
            for whitelisted_domain in self.whitelist_domains:
                if domain == whitelisted_domain or domain.endswith('.' + whitelisted_domain):
                    return {'is_whitelisted': True, 'match_type': 'subdomain', 'matched_entry': whitelisted_domain}
        return {'is_whitelisted': False, 'match_type': 'not_found', 'matched_entry': None}
    
    def analyze_webpage(self, suspicious_html, legitimate_html, current_url, suspicious_url):
        # 개별 지표 선계산
        url_sim = self.calculate_url_similarity(current_url, suspicious_url)
        text_sim = self.calculate_text_similarity(suspicious_html, legitimate_html)
        dom_sim = self.calculate_dom_similarity(suspicious_html, legitimate_html)
        # ★ [수정] CodeBERT 대신 1.0 (100%) 반환
        semantic_score = self.calculate_semantic_similarity_codebert(suspicious_html, legitimate_html) 

        results = {
            'url_similarity': url_sim,
            'text_similarity': text_sim,
            'dom_similarity': dom_sim,
            'semantic_features': self.analyze_semantic_features(suspicious_html, legitimate_html),
            'semantic_similarity': semantic_score, # 1.0이 됨
            'internal_links': self.analyze_internal_links(suspicious_html, current_url),
            'iframe_analysis': self.analyze_iframes(suspicious_html, current_url),
            # ★ [신규] 로그인 폼 분석 추가
            'login_form_analysis': self.analyze_login_forms(suspicious_html, current_url),
            'scores': {
                'text': text_sim.get('cosine_similarity', 0.0),
                'dom': dom_sim.get('tree_edit_distance', 0.0),
                'semantic': semantic_score, # 1.0이 됨
                'url': url_sim.get('url_levenshtein', 0.0)
            },
            'risk_assessment': {}
        }
        results['risk_assessment'] = self.calculate_overall_risk(results)
        return results

    def analyze_with_baseline(self, suspicious_html, current_url):
        legit_html = self.baseline_html or ""
        # ★ [수정] baseline_url을 suspicious_url 인자 대신 legitimate_url (비교 기준 URL)로 사용
        return self.analyze_webpage(
            suspicious_html=suspicious_html,
            legitimate_html=legit_html,
            current_url=current_url, # 현재 접속한 URL
            suspicious_url=self.baseline_url # 기준 URL (예: http://localhost:8000/normal.html#)
        )
    
    # ==================== 0. CodeBERT 시맨틱 유사도 (제거됨) ====================

    def calculate_semantic_similarity_codebert(self, html1: str, html2: str) -> float:
        """ ★ [수정] CodeBERT 기능을 사용하지 않음 (페널티 방지를 위해 1.0 반환)"""
        return 1.0
        
    # ==================== 1. 텍스트 유사도 ====================
    
    def calculate_text_similarity(self, html1, html2):
        text1 = self._extract_text(html1)
        text2 = self._extract_text(html2)
        return {
            'jaccard_similarity': self._jaccard_similarity(text1, text2),
            'cosine_similarity': self._cosine_similarity_tfidf(text1, text2),
            'levenshtein_similarity': self._levenshtein_similarity(text1, text2)
        }
    
    def _extract_text(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup(['script', 'style', 'meta', 'link']):
            tag.decompose()
        return soup.get_text(separator=' ', strip=True)
    
    def _jaccard_similarity(self, text1, text2):
        set1 = set(text1.lower().split())
        set2 = set(text2.lower().split())
        if not set1 or not set2: return 0.0
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        return len(intersection) / len(union)
    
    def _cosine_similarity_tfidf(self, text1, text2):
        try:
            vectorizer = TfidfVectorizer()
            tfidf_matrix = vectorizer.fit_transform([text1, text2])
            return cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
        except Exception: return 0.0
    
    def _levenshtein_similarity(self, text1, text2):
        if len(text1) > 1000: text1 = text1[:1000]
        if len(text2) > 1000: text2 = text2[:1000]
        distance = Levenshtein.distance(text1, text2)
        max_len = max(len(text1), len(text2))
        return 1 - (distance / max_len) if max_len > 0 else 0.0
    
    # ==================== 2. DOM 구조 비교 ====================
    
    def calculate_dom_similarity(self, html1, html2):
        return {
            'tree_edit_distance': self._tree_edit_distance(html1, html2),
            'structural_similarity': self._structural_similarity(html1, html2)
        }
    
    def _parse_dom_tree(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        body = soup.body if soup.body else soup
        if not body: return Node("empty") # body 태그 등이 아예 없는 경우
        return self._build_tree(body)
    
    def _build_tree(self, element, max_depth=10, current_depth=0):
        if current_depth >= max_depth:
            return Node(element.name or 'text')
        label = element.name or 'text'
        if element.name and element.get('id'):
            label += f"#{element.get('id')}"
        node = Node(label)
        if hasattr(element, 'children'):
            for child in element.children:
                if hasattr(child, 'name') and child.name:
                    node.addkid(self._build_tree(child, max_depth, current_depth + 1))
        return node
    
    def _tree_edit_distance(self, html1, html2):
        try:
            tree1 = self._parse_dom_tree(html1)
            tree2 = self._parse_dom_tree(html2)
            distance = simple_distance(tree1, tree2)
            max_size = max(self._count_nodes(tree1), self._count_nodes(tree2))
            similarity = 1 - (distance / max_size) if max_size > 0 else 0.0
            return similarity
        except Exception: return 0.0
    
    def _count_nodes(self, node):
        count = 1
        for child in node.children:
            count += self._count_nodes(child)
        return count
    
    def _structural_similarity(self, html1, html2):
        soup1 = BeautifulSoup(html1, 'html.parser')
        soup2 = BeautifulSoup(html2, 'html.parser')
        features1 = self._extract_structural_features(soup1)
        features2 = self._extract_structural_features(soup2)
        similarity_scores = []
        for key in features1.keys():
            if key in features2:
                diff = abs(features1[key] - features2[key])
                max_val = max(features1[key], features2[key])
                similarity_scores.append(1 - (diff / max_val) if max_val > 0 else 1)
        return np.mean(similarity_scores) if similarity_scores else 0.0
    
    def _extract_structural_features(self, soup):
        return {
            'div_count': len(soup.find_all('div')),
            'form_count': len(soup.find_all('form')),
            'input_count': len(soup.find_all('input')),
            'a_count': len(soup.find_all('a')),
            'depth': self._calculate_max_depth(soup.body if soup.body else soup)
        }
    
    def _calculate_max_depth(self, element, current_depth=0):
        if not element or not hasattr(element, 'children'):
            return current_depth
        max_child_depth = current_depth
        for child in element.children:
            if hasattr(child, 'name') and child.name:
                depth = self._calculate_max_depth(child, current_depth + 1)
                max_child_depth = max(max_child_depth, depth)
        return max_child_depth
    
    # ==================== 3. 의미 기반 분석 (키워드) ====================
    
    def analyze_semantic_features(self, html1, html2):
        features1 = self._extract_semantic_features(html1)
        features2 = self._extract_semantic_features(html2)
        return {
            'suspicious_features': features1,
            'legitimate_features': features2,
            'feature_match_score': self._compare_features(features1, features2)
        }
    
    def _extract_semantic_features(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text().lower()
        return {
            'has_login_form': bool(soup.find('input', {'type': 'password'})),
            'has_urgent_keywords': self._check_keywords(text, ['긴급', '즉시', '차단', '정지', 'urgent', 'immediate', 'suspended']),
            'password_input_count': len(soup.find_all('input', {'type': 'password'}))
        }
    
    def _check_keywords(self, text, keywords):
        return any(keyword in text for keyword in keywords)
    
    def _compare_features(self, features1, features2):
        matching_features = sum(1 for key in features1.keys() if features1[key] == features2[key])
        total_features = len(features1)
        return matching_features / total_features if total_features > 0 else 0.0
    
    # ==================== 4. URL 유사도 ====================
    
    def calculate_url_similarity(self, url1, url2):
        return {
            'domain_match': self._check_domain_match(url1, url2),
            'url_levenshtein': self._url_levenshtein_similarity(url1, url2),
            'suspicious_patterns': self._check_suspicious_url_patterns(url1, url2)
        }
    
    def _check_domain_match(self, url1, url2):
        try:
            domain1 = self._extract_domain(url1) # 현재 URL
            domain2 = self._extract_domain(url2) # 기준 URL
            if domain1 == domain2:
                return {'match': True, 'type': 'exact'}
            main1 = '.'.join(domain1.split('.')[-2:])
            main2 = '.'.join(domain2.split('.')[-2:])
            if main1 == main2:
                return {'match': True, 'type': 'main_domain'}
            return {'match': False, 'type': 'different'}
        except Exception:
            return {'match': False, 'type': 'error'}
    
    def _url_levenshtein_similarity(self, url1, url2):
        distance = Levenshtein.distance(url1.lower(), url2.lower())
        max_len = max(len(url1), len(url2))
        return 1 - (distance / max_len) if max_len > 0 else 0.0
    
    def _check_suspicious_url_patterns(self, url1, url2):
        suspicious = []
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url1):
            suspicious.append('IP 주소 직접 사용')
        if len(url1) > 100:
            suspicious.append('비정상적으로 긴 URL')
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(url1.endswith(tld) for tld in suspicious_tlds):
            suspicious.append(f'의심스러운 최상위 도메인 사용')
        url2_domain = self._extract_domain(url2)
        url1_domain = self._extract_domain(url1)
        if url1_domain != url2_domain and Levenshtein.distance(url1_domain, url2_domain) <= 2:
            suspicious.append('유사 도메인 탐지 (타이포스쿼팅 가능성)')
        return suspicious

    # ★ [신규] 4-1. 로그인 폼 URL 고도화
    def analyze_login_forms(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        base_domain = self._extract_domain(base_url)
        suspicious_forms = []
        password_inputs = soup.find_all('input', {'type': 'password'})
        
        for input_field in password_inputs:
            form = input_field.find_parent('form')
            if not form: continue

            action_url_raw = form.get('action', '')
            action_url_abs = urljoin(base_url, action_url_raw)
            action_domain = self._extract_domain(action_url_abs)

            # 현재 URL 도메인과 폼 액션 도메인이 다를 경우
            if base_domain and action_domain and base_domain != action_domain:
                suspicious_forms.append({
                    'action_url': action_url_abs,
                    'reason': f"로그인 폼이 외부 도메인({action_domain})으로 데이터를 전송합니다."
                })
        
        return {
            'total_login_forms': len(password_inputs),
            'suspicious_forms': suspicious_forms
        }
    
    # ==================== 5. 내부 링크 URL 추출 및 검사 (고도화) ====================
    
    def analyze_internal_links(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = soup.find_all('a', href=True)
        analysis = {'total_links': 0, 'internal_links': [], 'external_links': [], 'suspicious_links': []}
        try:
            base_domain = self._extract_domain(base_url)
        except Exception:
            base_domain = ""

        for link in links:
            href = link.get('href', '').strip()
            
            # ★ [수정] javascript:, mailto:, #만 있는 링크 등은 유효 링크에서 제외
            if not href or href.startswith(('javascript:', 'mailto:', '#', 'tel:')):
                continue
            
            analysis['total_links'] += 1 # 유효 링크 카운트
            absolute_url = urljoin(base_url, href)
            link_domain = self._extract_domain(absolute_url)
            
            link_info = {
                'url': absolute_url,
                'text': link.get_text(strip=True)[:50],
                'is_internal': False
            }

            if base_domain and link_domain == base_domain:
                link_info['is_internal'] = True
                analysis['internal_links'].append(link_info)
            else:
                analysis['external_links'].append(link_info)
            
            suspicion = self._is_suspicious_link(absolute_url, link.get_text(strip=True))
            if suspicion['is_suspicious']:
                link_info['reason'] = suspicion['reason']
                analysis['suspicious_links'].append(link_info)
        return analysis
    
    def _is_suspicious_link(self, url, text):
        """ ★ [수정] 링크가 의심스러운지 확인 (고도화) """
        reasons = []
        
        # 텍스트와 실제 URL 도메인 불일치
        if text and 'http' in text.lower():
            try:
                text_domain = self._extract_domain(text.strip().split()[0]) # 텍스트 중 첫 단어
                url_domain = self._extract_domain(url)
                if text_domain and url_domain and text_domain != url_domain:
                    reasons.append(f"링크 텍스트 도메인({text_domain})과 실제 도메인({url_domain}) 불일치")
            except Exception:
                pass # URL 파싱 실패 시 무시

        shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly']
        if any(shortener in url for shortener in shorteners):
            reasons.append('단축 URL 사용')
        
        return {
            'is_suspicious': bool(reasons),
            'reason': ', '.join(reasons) if reasons else '알 수 없는 이유'
        }
    
    # ==================== 6. iframe 화이트리스트 검사 ====================
    
    def analyze_iframes(self, html, current_url):
        soup = BeautifulSoup(html, 'html.parser')
        iframes = soup.find_all('iframe')
        analysis = {'total_iframes': len(iframes), 'whitelisted_iframes': [], 'suspicious_iframes': [], 'risk_level': 'low'}
        
        for idx, iframe in enumerate(iframes):
            iframe_info = self._analyze_single_iframe(iframe, current_url, idx)
            if iframe_info['is_whitelisted']:
                analysis['whitelisted_iframes'].append(iframe_info)
            else:
                analysis['suspicious_iframes'].append(iframe_info)
        
        suspicious_count = len(analysis['suspicious_iframes'])
        if suspicious_count == 0:
            analysis['risk_level'] = 'low'
        elif suspicious_count <= 2:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'high'
        return analysis
    
    def _analyze_single_iframe(self, iframe, current_url, index):
        src = iframe.get('src', '')
        width = iframe.get('width', '')
        height = iframe.get('height', '')
        style = iframe.get('style', '')
        iframe_info = {'index': index, 'src': src, 'is_whitelisted': False, 'match_info': {}, 'warnings': []}
        
        if src:
            whitelist_check = self.is_url_whitelisted(src)
            iframe_info['is_whitelisted'] = whitelist_check['is_whitelisted']
            iframe_info['match_info'] = whitelist_check
            if not whitelist_check['is_whitelisted']:
                iframe_info['warnings'].append("⚠️ 경고: 검증되지 않은 URL입니다.")
        else:
            iframe_info['warnings'].append("⚠️ src 속성이 없는 iframe입니다.")
        
        if self._is_hidden_iframe(width, height, style):
            iframe_info['warnings'].append("🔴 숨겨진 iframe이 탐지되었습니다.")
            iframe_info['is_whitelisted'] = False
        if src and self._has_suspicious_src_pattern(src):
            iframe_info['warnings'].append("🔴 의심스러운 src 패턴이 발견되었습니다.")
            iframe_info['is_whitelisted'] = False
        
        return iframe_info
    
    def _extract_domain(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception: return ""
    
    def _is_hidden_iframe(self, width, height, style):
        try:
            if width and int(re.sub(r'[^\d]', '', str(width))) <= 1: return True
            if height and int(re.sub(r'[^\d]', '', str(height))) <= 1: return True
        except Exception: pass
        hidden_patterns = [r'display:\s*none', r'visibility:\s*hidden', r'opacity:\s*0']
        return any(re.search(pattern, style, re.IGNORECASE) for pattern in hidden_patterns)
    
    def _has_suspicious_src_pattern(self, src):
        suspicious_patterns = [r'data:text/html', r'javascript:', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}']
        return any(re.search(pattern, src, re.IGNORECASE) for pattern in suspicious_patterns)
    
    # ==================== 7. 종합 위험도 평가 (CodeBERT 제외) ====================
    
    def calculate_overall_risk(self, results):
        """ ★ [수정] 종합 위험도 계산 (CodeBERT 페널티 제거, 로그인 폼 페널티 추가) """
        risk_score = 0
        warnings = []
        
        # 1. URL 유사도 (20점)
        if not results['url_similarity']['domain_match']['match']:
            risk_score += 20
            warnings.append('도메인이 정상 사이트와 다릅니다.')
        if results['url_similarity']['suspicious_patterns']:
            risk_score += 10
            warnings.extend(results['url_similarity']['suspicious_patterns'])
        
        # 2. 텍스트 유사도 (20점)
        text_sim = results['text_similarity']['cosine_similarity']
        if text_sim < 0.5:
            risk_score += 20
            warnings.append(f"텍스트 유사도가 낮습니다 ({text_sim:.2f})")
        elif text_sim < 0.7:
            risk_score += 10
        
        # 3. DOM 구조 유사도 (15점)
        dom_sim = results['dom_similarity']['tree_edit_distance']
        if dom_sim < 0.5:
            risk_score += 15
            warnings.append(f"DOM 구조가 크게 다릅니다 ({dom_sim:.2f})")
        elif dom_sim < 0.7:
            risk_score += 7
        
        # 4. 의미/폼 분석 (25점)
        semantic = results['semantic_features']['suspicious_features']
        
        # ★ [제거] CodeBERT 시맨틱 유사도 페널티 제거 (정상 vs 정상 오류 해결)
        
        if semantic['has_urgent_keywords']:
            risk_score += 10
            warnings.append('긴급 키워드가 발견되었습니다.')
        
        # ★ [신규] 로그인 폼 분석 페널티 (고도화)
        login_form_analysis = results['login_form_analysis']
        if login_form_analysis['suspicious_forms']:
            risk_score += 20 # (높은 페널티)
            warnings.append(login_form_analysis['suspicious_forms'][0]['reason'])
        
        # 5. 내부 링크 분석 (10점)
        if results['internal_links']['suspicious_links']:
            risk_score += 10
            warnings.append(f"{len(results['internal_links']['suspicious_links'])}개의 의심스러운 링크가 있습니다.")
        
        # 6. iframe 분석 (20점)
        iframe_analysis = results['iframe_analysis']
        if iframe_analysis['risk_level'] == 'medium':
            risk_score += 10
        elif iframe_analysis['risk_level'] == 'high':
            risk_score += 20
        
        # ★ [수정] 위험도 점수 최대 100점으로 제한
        risk_score = min(risk_score, 100)

        # 위험도 등급
        if risk_score >= 60:
            level = 'high'
        elif risk_score >= 30:
            level = 'medium'
        else:
            level = 'low'
        
        return {
            'risk_score': risk_score,
            'risk_level': level,
            'warnings': warnings
        }