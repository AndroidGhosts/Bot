import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import json
import re
import ssl
from urllib.parse import urlparse
import os
from datetime import datetime
from bs4 import BeautifulSoup
import whois

# تعطيل تحذيرات HTTPS غير الموثوقة
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# رابط قناتك
TELEGRAM_CHANNEL = "https://t.me/Android_Ghosts"

# قواعد بيانات متقدمة
ADVANCED_SOURCES = [
    "https://crt.sh/?q={}&output=json",
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
    "https://api.subdomain.center/?domain={}",
    "https://api.hackertarget.com/hostsearch/?q={}",
    "https://sonar.omnisint.io/subdomains/{}"
]

# قوائم سبردومينات مخصصة
CUSTOM_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'blog', 'api', 'admin', 'shop', 'store', 
    'forum', 'support', 'help', 'docs', 'dev', 'test', 'staging',
    'app', 'apps', 'cdn', 'static', 'assets', 'media', 'img', 'images',
    'upload', 'download', 'portal', 'login', 'auth', 'secure',
    'dashboard', 'panel', 'wordpress', 'wp', 'joomla', 'drupal'
]

# CDN detection patterns
CDN_PROVIDERS = {
    'Cloudflare': ['cloudflare', 'cf-'],
    'CloudFront': ['cloudfront', 'awsdns'],
    'Akamai': ['akamai', 'akamaiedge'],
    'Fastly': ['fastly', 'fastly.net'],
    'Azure CDN': ['azureedge'],
    'Google Cloud CDN': ['googleusercontent']
}

# Create session with common settings
SESSION = requests.Session()
SESSION.verify = False
SESSION.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
})

class UltimateDomainScanner:
    def __init__(self):
        self.subdomain_list = CUSTOM_SUBDOMAINS
        
    def get_tls_info(self, hostname):
        """معلومات TLS/SSL"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = {}
                    issuer = {}
                    
                    if cert and 'subject' in cert:
                        for item in cert['subject']:
                            for key, value in item:
                                subject[key] = value
                    
                    if cert and 'issuer' in cert:
                        for item in cert['issuer']:
                            for key, value in item:
                                issuer[key] = value
                    
                    return {
                        'protocol': ssock.version(),
                        'cipher_suite': ssock.cipher()[0] if ssock.cipher() else 'Unknown',
                        'subject': subject,
                        'issuer': issuer
                    }
        except Exception as e:
            return None
    
    def get_technologies(self, hostname):
        """كشف التقنيات المستخدمة"""
        technologies = {
            'web_servers': [],
            'programming_languages': [],
            'cms': []
        }
        
        try:
            response = SESSION.get(f"https://{hostname}", timeout=10)
            headers = response.headers
            content = response.text
            
            # كشف سيرفرات الويب
            if 'server' in headers:
                server = headers['server'].lower()
                if 'apache' in server:
                    technologies['web_servers'].append('Apache')
                if 'nginx' in server:
                    technologies['web_servers'].append('Nginx')
                if 'iis' in server:
                    technologies['web_servers'].append('IIS')
            
            # كشف لغات البرمجة
            if '.php' in content or 'php' in content.lower():
                technologies['programming_languages'].append('PHP')
            if 'wordpress' in content.lower():
                technologies['cms'].append('WordPress')
            if 'drupal' in content.lower():
                technologies['cms'].append('Drupal')
            if 'joomla' in content.lower():
                technologies['cms'].append('Joomla')
            
            return technologies
            
        except:
            return technologies
    
    def detect_cdn(self, hostname):
        """كشف مزودي CDN"""
        cdn_info = {'provider': None, 'cname': None}
        
        try:
            # فحص CNAME
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).lower()
                    cdn_info['cname'] = cname
                    for provider, patterns in CDN_PROVIDERS.items():
                        for pattern in patterns:
                            if pattern.lower() in cname:
                                cdn_info['provider'] = provider
                                return cdn_info
            except:
                pass
            
            # فحص الرؤوس
            headers = self.get_http_headers(hostname)
            for provider, patterns in CDN_PROVIDERS.items():
                for pattern in patterns:
                    for header, value in headers.items():
                        if pattern.lower() in str(value).lower():
                            cdn_info['provider'] = provider
                            return cdn_info
            
        except:
            pass
        
        return cdn_info
    
    def get_http_headers(self, url):
        """الحصول على رؤوس HTTP"""
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            response = SESSION.head(url, timeout=10, allow_redirects=True)
            return dict(response.headers)
        except:
            return {}
    
    def find_linked_assets(self, hostname):
        """اكتشاف الأصول المرتبطة"""
        linked_assets = set()
        
        try:
            if not hostname.startswith('http'):
                url = f"https://{hostname}"
            else:
                url = hostname

            response = SESSION.get(url, timeout=15)
            content = response.text
            
            # البحث عن أنماط
            patterns = [
                r'src=["\'](https?://[^"\']+)["\']',
                r'href=["\'](https?://[^"\']+)["\']',
                r'url\(["\']?(https?://[^"\')]+)["\']?\)'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    parsed = urlparse(match)
                    if parsed.netloc and parsed.netloc != hostname:
                        linked_assets.add(parsed.netloc)
            
        except:
            pass
        
        return linked_assets
    
    def query_advanced_source(self, url, domain):
        """استعلام مصادر متقدمة"""
        try:
            formatted_url = url.format(domain)
            response = SESSION.get(formatted_url, timeout=30)
            
            if response.status_code == 200:
                if 'crt.sh' in url:
                    data = response.json()
                    return [item['name_value'].lower().strip() for item in data if domain in item['name_value']]
                elif 'certspotter' in url:
                    data = response.json()
                    subdomains = []
                    for item in data:
                        for name in item.get('dns_names', []):
                            if domain in name:
                                subdomains.append(name.lower().strip())
                    return subdomains
                elif 'hackertarget' in url:
                    data = response.text
                    return [line.split(',')[0].strip() for line in data.split('\n') if domain in line]
                elif 'subdomain.center' in url:
                    data = response.json()
                    return data if isinstance(data, list) else []
                elif 'sonar.omnisint' in url:
                    data = response.json()
                    return data if isinstance(data, list) else []
        except:
            pass
        return []
    
    def advanced_subdomain_discovery(self, domain):
        """اكتشاف سبردومينات متقدم"""
        all_subdomains = set()
        
        # البحث في المصادر المتقدمة
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.query_advanced_source, url, domain) for url in ADVANCED_SOURCES]
            
            for future in futures:
                try:
                    subdomains = future.result(timeout=30)
                    for sub in subdomains:
                        sub = sub.lower().strip()
                        sub = re.sub(r'^\.', '', sub)
                        sub = re.sub(r'^\*\.', '', sub)
                        if domain in sub:
                            all_subdomains.add(sub)
                except:
                    continue
        
        # DNS Brute Force
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for sub in self.subdomain_list:
                full_domain = f"{sub}.{domain}"
                futures.append(executor.submit(self.check_domain, full_domain))
            
            for future in futures:
                try:
                    result = future.result(timeout=3)
                    if result:
                        all_subdomains.add(result)
                except:
                    pass
        
        return sorted(all_subdomains)
    
    def check_domain(self, domain):
        """فحص النطاق"""
        try:
            socket.gethostbyname(domain)
            return domain
        except:
            return None
    
    def comprehensive_analysis(self, hostname):
        """تحليل شامل للنطاق"""
        result = {
            'hostname': hostname,
            'ip': None,
            'tls_info': None,
            'cdn': None,
            'technologies': None,
            'linked_assets': []
        }
        
        try:
            # المعلومات الأساسية
            result['ip'] = socket.gethostbyname(hostname)
            
            # معلومات متقدمة
            result['tls_info'] = self.get_tls_info(hostname)
            result['cdn'] = self.detect_cdn(hostname)
            result['technologies'] = self.get_technologies(hostname)
            result['linked_assets'] = list(self.find_linked_assets(hostname))
            
        except:
            pass
        
        return result

# إنشاء الماسح الضوئي المتقدم
scanner = UltimateDomainScanner()

def github_scan_domain(domain):
    """وظيفة المسح للنطاق لـ GitHub Actions"""
    print(f"🚀 بدء الفحص العميق لـ: {domain}")
    print("⏳ جاري جمع البيانات...")
    
    try:
        # التحليل الشامل للنطاق الرئيسي
        main_analysis = scanner.comprehensive_analysis(domain)
        
        print("🔍 جاري الاكتشاف المتقدم للسبردومينات...")
        all_subdomains = scanner.advanced_subdomain_discovery(domain)
        
        print("🔍 جاري تحليل السبردومينات النشطة...")
        active_subdomains = []
        for subdomain in all_subdomains[:20]:
            try:
                analysis = scanner.comprehensive_analysis(subdomain)
                if analysis['ip']:
                    active_subdomains.append(analysis)
            except:
                continue
        
        # بناء التقرير الشامل
        report = f"""🔬 تقرير الفحص العميق: {domain}

📊 إحصائيات الاكتشاف:
• السبردومينات المكتشفة: {len(all_subdomains)}
• السبردومينات النشطة: {len(active_subdomains)}

🌐 المعلومات الأساسية:"""
        
        if main_analysis['ip']:
            report += f"""
• النطاق: {main_analysis['hostname']}
• IP: {main_analysis['ip']}"""
        
        if main_analysis['cdn']['provider']:
            report += f"""
• CDN: {main_analysis['cdn']['provider']}"""
        
        if main_analysis['tls_info']:
            report += f"""
• بروتوكول: {main_analysis['tls_info']['protocol']}"""
        
        # معلومات التقنيات
        if main_analysis['technologies']:
            report += f"""
🔧 التقنيات المكتشفة:"""
            tech = main_analysis['technologies']
            if tech['web_servers']:
                report += f"""
• سيرفرات الويب: {', '.join(tech['web_servers'])}"""
            if tech['programming_languages']:
                report += f"""
• لغات البرمجة: {', '.join(tech['programming_languages'])}"""
            if tech['cms']:
                report += f"""
• أنظمة إدارة المحتوى: {', '.join(tech['cms'])}"""
        
        # السبردومينات النشطة
        if active_subdomains:
            report += f"""
🌐 أهم السبردومينات النشطة:"""
            for i, sub in enumerate(active_subdomains[:8], 1):
                cdn_info = f" | CDN: {sub['cdn']['provider']}" if sub['cdn']['provider'] else ""
                report += f"""
{i}. {sub['hostname']}{cdn_info}"""
        
        # الأصول المرتبطة
        if main_analysis['linked_assets']:
            report += f"""
🔗 الأصول الخارجية المرتبطة:"""
            for asset in list(main_analysis['linked_assets'])[:5]:
                report += f"""
• {asset}"""
        
        report += f"""

✅ تم الفحص العميق بنجاح!

🔗 انضم لقناتنا: {TELEGRAM_CHANNEL}"""
        
        return report
        
    except Exception as e:
        return f"❌ خطأ في فحص النطاق: {str(e)}"

if __name__ == '__main__':
    # اختبار إذا كان يعمل على GitHub Actions
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        domain = os.environ.get('SCAN_DOMAIN', 'example.com')
        result = github_scan_domain(domain)
        print(result)
        
        # حفظ النتيجة في ملف
        with open('scan_result.txt', 'w', encoding='utf-8') as f:
            f.write(result)
        print("✅ تم حفظ النتيجة في scan_result.txt")
    else:
        # تشغيل محلي للاختبار
        domain = input("أدخل النطاق للفحص: ").strip()
        if domain:
            result = github_scan_domain(domain)
            print(result)
        else:
            print("❌ لم تدخل نطاقاً للفحص")
