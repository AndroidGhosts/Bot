import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import json
import re
import ssl
from urllib.parse import urlparse
import time
import urllib3
import os
from datetime import datetime
import asyncio
import threading
from bs4 import BeautifulSoup
import whois
import ipaddress

# تعطيل تحذيرات HTTPS غير الموثوقة
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# التوكن الخاص بك
TOKEN = "8563380581:AAFKao_OiIt0hQast08QklEQsqFUm4UjFZA"

# رابط قناتك
TELEGRAM_CHANNEL = "https://t.me/Android_Ghosts"

# قواعد بيانات متقدمة
ADVANCED_SOURCES = [
    "https://crt.sh/?q={}&output=json",
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
    "https://api.subdomain.center/?domain={}",
    "https://api.hackertarget.com/hostsearch/?q={}",
    "https://sonar.omnisint.io/subdomains/{}",
    "https://jldc.me/anubis/subdomains/{}"
]

# قوائم سبردومينات مخصصة
CUSTOM_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'blog', 'api',
    'admin', 'shop', 'store', 'forum', 'support', 'help', 'docs',
    'dev', 'test', 'staging', 'prod', 'backend', 'frontend', 'app', 'apps',
    'cdn', 'static', 'assets', 'media', 'img', 'images', 'video', 'music',
    'upload', 'download', 'storage', 'db', 'database', 'sql', 'nosql',
    'cache', 'redis', 'elastic', 'kibana', 'grafana', 'prometheus',
    'jenkins', 'git', 'svn', 'vpn', 'ssh', 'ftp', 'sftp',
    'webmail', 'email', 'owa', 'exchange', 'calendar',
    'portal', 'login', 'auth', 'secure', 'ssl', 'tls',
    'dashboard', 'panel', 'control', 'manager', 'adminer', 'phpmyadmin',
    'wordpress', 'wp', 'joomla', 'drupal', 'magento', 'shopify',
    'api-docs', 'swagger', 'graphql', 'rest', 'soap',
    'internal', 'private', 'secret', 'hidden', 'legacy', 'old', 'new',
    'beta', 'alpha', 'gamma', 'delta', 'uat', 'qa', 'demo', 'sandbox'
]

# CDN detection patterns
CDN_PROVIDERS = {
    'Cloudflare': ['cloudflare', 'cf-', 'cloudflare.com'],
    'CloudFront': ['cloudfront', 'awsdns', 'amazonaws'],
    'Akamai': ['akamai', 'akamaiedge', 'akamaihd'],
    'Fastly': ['fastly', 'fastly.net'],
    'Incapsula': ['incapdns', 'imperva'],
    'Azure CDN': ['azureedge', 'microsoft.com'],
    'Google Cloud CDN': ['googleusercontent', 'c.documentcloud', 'google'],
    'Sucuri': ['sucuri', 'sucuriscdn'],
    'StackPath': ['stackpathdns', 'stackpath'],
    'OVH CDN': ['cdn.ovh.net', 'ovh.com'],
    'BunnyCDN': ['b-cdn.net', 'bunnycdn'],
    'KeyCDN': ['kxcdn.com', 'keycdn'],
    'CDN77': ['cdn77.org', 'cdn77'],
    'Limelight': ['llnwd.net', 'limelight'],
    'EdgeCast': ['edgecastcdn.net', 'edgecast']
}

# WAF detection patterns
WAF_PROVIDERS = {
    'Cloudflare': ['cloudflare', '__cf', 'cf-ray'],
    'Akamai': ['akamai', 'akamaighost'],
    'Imperva': ['imperva', 'incap_ses'],
    'AWS WAF': ['awselb', 'aws', 'x-aws-id'],
    'Sucuri': ['sucuri', 'x-sucuri-id'],
    'Fortinet': ['fortigate', 'fortinet'],
    'F5 BIG-IP': ['bigip', 'f5', 'x-wa-info'],
    'Barracuda': ['barracuda'],
    'Citrix NetScaler': ['citrix', 'netscaler'],
    'ModSecurity': ['mod_security']
}

# Create session with common settings
SESSION = requests.Session()
SESSION.verify = False
SESSION.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive'
})

class UltimateDomainScanner:
    def __init__(self):
        self.subdomain_list = CUSTOM_SUBDOMAINS
        self.discovered_subdomains = set()
        
    def advanced_dns_queries(self, domain):
        """استعلامات DNS متقدمة"""
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                dns_records[record_type] = []
        
        return dns_records
    
    def get_advanced_tls_info(self, hostname):
        """معلومات TLS/SSL متقدمة بدون cryptography"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # تحليل الشهادة بدون cryptography
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
                        'issuer': issuer,
                        'valid_from': cert.get('notBefore', '') if cert else '',
                        'valid_to': cert.get('notAfter', '') if cert else '',
                    }
        except Exception as e:
            return None
    
    def detect_waf(self, hostname):
        """كشف جدار الحماية (WAF)"""
        waf_info = {'provider': None, 'indicators': []}
        
        try:
            headers = self.get_http_headers(hostname)
            
            for provider, patterns in WAF_PROVIDERS.items():
                for pattern in patterns:
                    # البحث في الرؤوس
                    for header, value in headers.items():
                        if pattern.lower() in str(value).lower():
                            waf_info['provider'] = provider
                            waf_info['indicators'].append(f"{header}: {value}")
                    
                    # البحث في محتوى الاستجابة
                    try:
                        response = SESSION.get(f"https://{hostname}", timeout=10)
                        if pattern.lower() in response.text.lower():
                            waf_info['provider'] = provider
                            waf_info['indicators'].append("Found in response body")
                    except:
                        pass
            
            return waf_info
        except:
            return waf_info
    
    def port_scan(self, hostname, ports=[80, 443, 22, 21, 25, 53, 8080, 8443, 3000, 5000]):
        """فحص المنافذ الأساسية"""
        open_ports = []
        
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((hostname, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                pass
        
        return open_ports
    
    def get_technologies(self, hostname):
        """كشف التقنيات المستخدمة"""
        technologies = {
            'web_servers': [],
            'programming_languages': [],
            'frameworks': [],
            'databases': [],
            'cms': [],
            'analytics': [],
            'javascript': []
        }
        
        try:
            response = SESSION.get(f"https://{hostname}", timeout=10)
            headers = response.headers
            content = response.text
            
            # كشف سيرفرات الويب
            server_indicators = {
                'Apache': ['apache', 'httpd'],
                'Nginx': ['nginx'],
                'IIS': ['microsoft-iis', 'iis'],
                'LiteSpeed': ['litespeed'],
                'Cloudflare': ['cloudflare'],
                'Tomcat': ['tomcat', 'apache-tomcat']
            }
            
            for server, indicators in server_indicators.items():
                for indicator in indicators:
                    if 'server' in headers and indicator in headers['server'].lower():
                        technologies['web_servers'].append(server)
                    if indicator in content.lower():
                        technologies['web_servers'].append(server)
            
            # كشف لغات البرمجة
            lang_indicators = {
                'PHP': ['.php', 'php', 'x-powered-by: php'],
                'Python': ['python', 'django', 'flask'],
                'Ruby': ['ruby', 'rails', 'rack'],
                'JavaScript': ['node.js', 'express', 'react', 'angular', 'vue'],
                'Java': ['java', 'jsp', 'servlet'],
                '.NET': ['.net', 'asp.net', 'x-aspnet-version']
            }
            
            for lang, indicators in lang_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in content.lower():
                        technologies['programming_languages'].append(lang)
                    if 'x-powered-by' in headers and indicator.lower() in headers['x-powered-by'].lower():
                        technologies['programming_languages'].append(lang)
            
            # كشف أنظمة إدارة المحتوى
            cms_indicators = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'media/joomla'],
                'Drupal': ['drupal', 'sites/all'],
                'Magento': ['magento', 'static/version'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'Wix': ['wix.com', 'wixpress'],
                'Squarespace': ['squarespace']
            }
            
            for cms, indicators in cms_indicators.items():
                for indicator in indicators:
                    if indicator in content.lower():
                        technologies['cms'].append(cms)
            
            # كشف أدوات التحليلات
            analytics_indicators = {
                'Google Analytics': ['google-analytics', 'ga.js', 'analytics.js'],
                'Google Tag Manager': ['gtm.js', 'googletagmanager'],
                'Facebook Pixel': ['facebook.net', 'fbq('],
                'Hotjar': ['hotjar'],
                'Matomo': ['matomo', 'piwik.js']
            }
            
            for analytic, indicators in analytics_indicators.items():
                for indicator in indicators:
                    if indicator in content.lower():
                        technologies['analytics'].append(analytic)
            
            return technologies
            
        except:
            return technologies
    
    def get_domain_info(self, domain):
        """معلومات النطاق (WHOIS)"""
        try:
            domain_info = whois.whois(domain)
            return {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'status': domain_info.status,
                'emails': domain_info.emails
            }
        except:
            return {}
    
    def get_http_headers(self, url):
        """الحصول على رؤوس HTTP"""
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            response = SESSION.head(url, timeout=10, allow_redirects=True)
            return dict(response.headers)
        except:
            return {}
    
    def detect_cdn(self, hostname):
        """كشف مزودي CDN"""
        cdn_info = {'provider': None, 'cname': None, 'confidence': 'low'}
        
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
                                cdn_info['confidence'] = 'high'
                                return cdn_info
            except:
                pass
            
            # فحص IP
            try:
                ip = socket.gethostbyname(hostname)
                for provider, patterns in CDN_PROVIDERS.items():
                    for pattern in patterns:
                        if pattern.lower() in ip.lower():
                            cdn_info['provider'] = provider
                            cdn_info['confidence'] = 'medium'
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
                            cdn_info['confidence'] = 'medium'
                            return cdn_info
            
        except:
            pass
        
        return cdn_info
    
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
            
            # استخدام BeautifulSoup لتحليل أكثر دقة
            soup = BeautifulSoup(content, 'html.parser')
            
            # جميع الروابط الخارجية
            for link in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'source']):
                src = link.get('src') or link.get('href') or link.get('data-src')
                if src and src.startswith('http'):
                    parsed = urlparse(src)
                    if parsed.netloc and parsed.netloc != hostname:
                        linked_assets.add(parsed.netloc)
            
            # البحث عن أنماط إضافية
            patterns = [
                r'["\'](https?://[^"\']+)["\']',
                r'url\(["\']?(https?://[^"\')]+)["\']?\)',
                r'["\'](//[^"\']+)["\']',
                r'window\.location[^=]*=[^"\' ]*["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match.startswith('//'):
                        match = 'https:' + match
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
                elif 'jldc.me' in url:
                    data = response.json()
                    return data if isinstance(data, list) else []
        except:
            pass
        return []
    
    def advanced_subdomain_discovery(self, domain):
        """اكتشاف سبردومينات متقدم"""
        all_subdomains = set()
        
        # البحث في المصادر المتقدمة
        with ThreadPoolExecutor(max_workers=10) as executor:
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
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for sub in self.subdomain_list:
                full_domain = f"{sub}.{domain}"
                futures.append(executor.submit(self.check_domain, full_domain))
            
            for future in futures:
                try:
                    result = future.result(timeout=5)
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
            'http_headers': None,
            'cdn': None,
            'waf': None,
            'technologies': None,
            'open_ports': [],
            'linked_assets': [],
            'dns_records': {},
            'domain_info': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # المعلومات الأساسية
            result['ip'] = socket.gethostbyname(hostname)
            
            # معلومات متقدمة
            result['tls_info'] = self.get_advanced_tls_info(hostname)
            result['http_headers'] = self.get_http_headers(hostname)
            result['cdn'] = self.detect_cdn(hostname)
            result['waf'] = self.detect_waf(hostname)
            result['technologies'] = self.get_technologies(hostname)
            result['open_ports'] = self.port_scan(hostname)
            result['linked_assets'] = list(self.find_linked_assets(hostname))
            result['domain_info'] = self.get_domain_info(hostname)
            
        except:
            pass
        
        return result

# إنشاء الماسح الضوئي المتقدم
scanner = UltimateDomainScanner()

# Telegram Bot Code (سيتم استبداله بـ GitHub Actions)
def run_telegram_bot():
    """تشغيل بوت التليجرام - للاستخدام المحلي فقط"""
    try:
        from telegram import Update
        from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
        
        async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            user = update.message.from_user
            welcome_text = f"""مرحباً {user.first_name}! 🚀

IPScannerGHOST Bot - الإصدار الأقوى على الإطلاق

أقوى بوت لتحليل النطاقات واكتشاف الثغرات

🔬 المميزات المتقدمة:
• اكتشاف سبردومينات متقدم من 6+ مصادر
• تحليل TLS/SSL متعمق
• كشف CDN + WAF + التقنيات المستخدمة
• فحص المنافذ المفتوحة
• تحليل WHOIS للنطاقات
• اكتشاف الأصول والموارد

🎯 الأوامر المتاحة:
/scan [نطاق] - فحص سريع
/fullscan [نطاق] - فحص شامل متقدم
/deepscan [نطاق] - فحص عميق شامل
/techscan [نطاق] - فحص التقنيات المستخدمة

🔗 انضم لقناتنا: {TELEGRAM_CHANNEL}

📝 مثال:
/fullscan example.com
/deepscan target.com"""
            await update.message.reply_text(welcome_text)

        async def deepscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not context.args:
                await update.message.reply_text("❌ يرجى إدخال نطاق (مثال: /deepscan example.com)")
                return
            
            domain = context.args[0].lower()
            processing_msg = await update.message.reply_text(f"🔬 بدء الفحص العميق لـ: {domain}\n⏳ قد يستغرق 3-5 دقائق...")
            
            try:
                # التحليل الشامل للنطاق الرئيسي
                main_analysis = scanner.comprehensive_analysis(domain)
                
                # اكتشاف السبردومينات المتقدم
                await processing_msg.edit_text(f"🔍 جاري الاكتشاف المتقدم للسبردومينات...")
                all_subdomains = scanner.advanced_subdomain_discovery(domain)
                
                # تحليل السبردومينات النشطة
                await processing_msg.edit_text(f"🔍 جاري تحليل السبردومينات النشطة...")
                active_subdomains = []
                for subdomain in all_subdomains[:50]:
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
                
                if main_analysis['waf']['provider']:
                    report += f"""
• WAF: {main_analysis['waf']['provider']}"""
                
                if main_analysis['open_ports']:
                    report += f"""
• المنافذ المفتوحة: {', '.join(map(str, main_analysis['open_ports']))}"""
                
                # التقنيات
                if main_analysis['technologies']:
                    report += f"""
🔧 التقنيات الرئيسية:"""
                    tech = main_analysis['technologies']
                    if tech['web_servers']:
                        report += f"""
• السيرفر: {', '.join(set(tech['web_servers']))}"""
                    if tech['programming_languages']:
                        report += f"""
• اللغات: {', '.join(set(tech['programming_languages']))}"""
                    if tech['cms']:
                        report += f"""
• CMS: {', '.join(set(tech['cms']))}"""
                
                # السبردومينات النشطة
                if active_subdomains:
                    report += f"""
🌐 أهم السبردومينات النشطة:"""
                    for i, sub in enumerate(active_subdomains[:10], 1):
                        cdn_info = f" | CDN: {sub['cdn']['provider']}" if sub['cdn']['provider'] else ""
                        report += f"""
{i}. {sub['hostname']}{cdn_info}"""
                
                report += f"""

✅ تم الفحص العميق بنجاح!

🔗 انضم لقناتنا: {TELEGRAM_CHANNEL}"""
                
                await processing_msg.edit_text(report)
                
            except Exception as e:
                await processing_msg.edit_text(f"❌ خطأ في الفحص العميق: {str(e)}")

        async def techscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not context.args:
                await update.message.reply_text("❌ يرجى إدخال نطاق (مثال: /techscan example.com)")
                return
            
            domain = context.args[0].lower()
            processing_msg = await update.message.reply_text(f"🔧 بدء فحص التقنيات لـ: {domain}...")
            
            try:
                analysis = scanner.comprehensive_analysis(domain)
                
                if not analysis['ip']:
                    await processing_msg.edit_text("❌ لم أتمكن من العثور على هذا النطاق")
                    return
                
                report = f"""🔧 تقرير التقنيات: {domain}

📍 المعلومات الأساسية:
• النطاق: {analysis['hostname']}
• IP: {analysis['ip']}"""
                
                if analysis['technologies']:
                    tech = analysis['technologies']
                    report += f"""
📊 التقنيات المكتشفة:"""
                    
                    if tech['web_servers']:
                        report += f"""
🖥️  سيرفرات الويب: {', '.join(set(tech['web_servers']))}"""
                    
                    if tech['programming_languages']:
                        report += f"""
💻 لغات البرمجة: {', '.join(set(tech['programming_languages']))}"""
                    
                    if tech['cms']:
                        report += f"""
📝 أنظمة إدارة المحتوى: {', '.join(set(tech['cms']))}"""
                    
                    if tech['analytics']:
                        report += f"""
📈 أدوات التحليلات: {', '.join(set(tech['analytics']))}"""
                
                if analysis['cdn']['provider']:
                    report += f"""
🌐 مزود CDN: {analysis['cdn']['provider']}"""
                
                if analysis['waf']['provider']:
                    report += f"""
🛡️  جدار الحماية: {analysis['waf']['provider']}"""
                
                report += f"""

🔗 انضم لقناتنا: {TELEGRAM_CHANNEL}"""
                
                await processing_msg.edit_text(report)
                
            except Exception as e:
                await processing_msg.edit_text(f"❌ خطأ في فحص التقنيات: {str(e)}")

        async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not context.args:
                await update.message.reply_text("❌ يرجى إدخال نطاق (مثال: /scan example.com)")
                return
            
            domain = context.args[0].lower()
            await update.message.reply_text(f"🔍 بدء الفحص السريع لـ: {domain}...")
            
            try:
                analysis = scanner.comprehensive_analysis(domain)
                
                if not analysis['ip']:
                    await update.message.reply_text("❌ لم أتمكن من العثور على هذا النطاق")
                    return
                
                report = f"""📊 تقرير الفحص السريع: {domain}

📍 المعلومات الأساسية:
• النطاق: {analysis['hostname']}
• IP: {analysis['ip']}"""

                if analysis['tls_info']:
                    report += f"""
🔒 معلومات TLS:
• البروتوكول: {analysis['tls_info']['protocol']}"""
                
                if analysis['cdn']['provider']:
                    report += f"""
🌐 معلومات CDN:
• المزود: {analysis['cdn']['provider']}"""
                
                if analysis['linked_assets']:
                    report += f"""
🔗 الأصول المرتبطة: {len(analysis['linked_assets'])}"""
                    for asset in list(analysis['linked_assets'])[:3]:
                        report += f"""
• {asset}"""
                
                report += f"""

💡 استخدم /deepscan {domain} للفحص الشامل

انضم لقناتنا: {TELEGRAM_CHANNEL}"""
                
                await update.message.reply_text(report)
                
            except Exception as e:
                await update.message.reply_text(f"❌ خطأ في الفحص: {str(e)}")

        async def fullscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not context.args:
                await update.message.reply_text("❌ يرجى إدخال نطاق (مثال: /fullscan example.com)")
                return
            
            domain = context.args[0].lower()
            processing_msg = await update.message.reply_text(f"🔍 بدء الفحص الشامل لـ: {domain}...")
            
            try:
                analysis = scanner.comprehensive_analysis(domain)
                all_subdomains = scanner.advanced_subdomain_discovery(domain)
                
                if not analysis['ip']:
                    await processing_msg.edit_text("❌ لم أتمكن من العثور على هذا النطاق")
                    return
                
                report = f"""📊 تقرير الفحص الشامل: {domain}

📈 الإحصائيات:
• السبردومينات المكتشفة: {len(all_subdomains)}

🌐 المعلومات الأساسية:
• النطاق: {analysis['hostname']}
• IP: {analysis['ip']}"""

                if analysis['cdn']['provider']:
                    report += f"""
• CDN: {analysis['cdn']['provider']}"""
                
                if analysis['waf']['provider']:
                    report += f"""
• WAF: {analysis['waf']['provider']}"""
                
                # التقنيات
                if analysis['technologies']:
                    report += f"""
🔧 التقنيات الرئيسية:"""
                    tech = analysis['technologies']
                    if tech['web_servers']:
                        report += f"""
• السيرفر: {', '.join(set(tech['web_servers']))}"""
                    if tech['programming_languages']:
                        report += f"""
• اللغات: {', '.join(set(tech['programming_languages']))}"""
                
                # أهم السبردومينات
                if all_subdomains:
                    report += f"""
🌐 أهم السبردومينات:"""
                    for i, sub in enumerate(all_subdomains[:8], 1):
                        report += f"""
{i}. {sub}"""
                
                report += f"""

💡 استخدم /deepscan {domain} للفحص العميق

انضم لقناتنا: {TELEGRAM_CHANNEL}"""
                
                await processing_msg.edit_text(report)
                
            except Exception as e:
                await processing_msg.edit_text(f"❌ خطأ في الفحص الشامل: {str(e)}")

        # تشغيل البوت
        application = Application.builder().token(TOKEN).build()
        
        application.add_handler(CommandHandler("start", start_command))
        application.add_handler(CommandHandler("scan", scan_command))
        application.add_handler(CommandHandler("fullscan", fullscan_command))
        application.add_handler(CommandHandler("deepscan", deepscan_command))
        application.add_handler(CommandHandler("techscan", techscan_command))
        
        print("✅ البوت يعمل على GitHub!")
        application.run_polling()
        
    except ImportError:
        print("⚠️  مكتبة telegram غير مثبتة - تشغيل وضع GitHub Actions")

# GitHub Actions Integration
def github_scan_domain(domain):
    """وظيفة المسح للنطاق لـ GitHub Actions"""
    print(f"🔍 بدء فحص النطاق: {domain}")
    
    try:
        # التحليل الشامل
        analysis = scanner.comprehensive_analysis(domain)
        all_subdomains = scanner.advanced_subdomain_discovery(domain)
        
        if not analysis['ip']:
            return f"❌ لم أتمكن من العثور على النطاق: {domain}"
        
        # بناء التقرير
        report = f"""
🔬 تقرير فحص النطاق: {domain}
📊 إحصائيات الاكتشاف:
• السبردومينات المكتشفة: {len(all_subdomains)}

🌐 المعلومات الأساسية:
• النطاق: {analysis['hostname']}
• IP: {analysis['ip']}"""

        if analysis['cdn']['provider']:
            report += f"""
• CDN: {analysis['cdn']['provider']}"""

        if analysis['waf']['provider']:
            report += f"""
• WAF: {analysis['waf']['provider']}"""

        if analysis['technologies']:
            tech = analysis['technologies']
            report += f"""
🔧 التقنيات المكتشفة:"""
            if tech['web_servers']:
                report += f"""
• سيرفرات الويب: {', '.join(set(tech['web_servers']))}"""
            if tech['programming_languages']:
                report += f"""
• لغات البرمجة: {', '.join(set(tech['programming_languages']))}"""
            if tech['cms']:
                report += f"""
• أنظمة إدارة المحتوى: {', '.join(set(tech['cms']))}"""

        if all_subdomains:
            report += f"""
🌐 أهم السبردومينات:"""
            for i, sub in enumerate(all_subdomains[:10], 1):
                report += f"""
{i}. {sub}"""

        report += f"""

✅ تم الفحص بنجاح!
🔗 القناة: {TELEGRAM_CHANNEL}"""
        
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
    else:
        # تشغيل بوت التليجرام للاستخدام المحلي
        run_telegram_bot()
