from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import csv
import os
from collections import defaultdict

app = Flask(__name__)

# Загрузка базы данных безопасных доменов
SAFE_DOMAINS_SET = set()
# Путь к CSV файлу (относительно папки sait)
# CSV находится в родительской директории
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_FILE = os.path.join(BASE_DIR, 'final_15million.csv')


def load_safe_domains():
    """Загружает безопасные домены из CSV файла"""
    global SAFE_DOMAINS_SET
    if not SAFE_DOMAINS_SET:
        print("🔄 Загрузка базы данных доменов...")
        try:
            count = 0
            with open(CSV_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row.get('domain', '').strip().lower()
                    label = row.get('label', '').strip().lower()
                    if domain and label == 'benign':
                        # В базе домены хранятся БЕЗ TLD (например, "google", а не "google.com")
                        SAFE_DOMAINS_SET.add(domain)
                        count += 1
                        if count % 100000 == 0:
                            print(f"  Загружено {count} доменов...")
            print(f"✅ Загружено {len(SAFE_DOMAINS_SET)} уникальных безопасных доменов")
        except Exception as e:
            print(f"⚠️ Ошибка загрузки базы данных: {e}")
            print("  Используется ограниченный список безопасных доменов")
            # Fallback список (БЕЗ TLD, как в базе)
            SAFE_DOMAINS_SET = {'google', 'youtube', 'facebook', 'twitter',
                                'instagram', 'github', 'stackoverflow', 'wikipedia',
                                'microsoft', 'apple', 'yandex', 'mail', 'vk'}
    return SAFE_DOMAINS_SET


# Загружаем базу при старте
load_safe_domains()

# Расширенный список подозрительных паттернов
SUSPICIOUS_PATTERNS = [
    (r'bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.link|ow\.ly|buff\.ly', 'Сервис сокращения ссылок'),
    (r'paypal.*\.ru|amazon.*\.ru|facebook.*\.ru|google.*\.ru|microsoft.*\.ru',
     'Поддельный домен известного бренда с .ru'),
    (r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', 'Использование IP-адреса вместо домена'),
    (r'[a-z0-9-]+\.(tk|ml|ga|cf|gq|xyz|top)', 'Подозрительный домен верхнего уровня'),
    (r'(secure|verify|account|update|confirm|login|signin).*\.(tk|ml|ga|cf)', 'Фишинговый паттерн в домене'),
    (r'[a-z0-9]{20,}\.[a-z]{2,}', 'Очень длинный случайный домен'),
    (r'[0-9]{4,}\.[a-z]', 'Домен начинается с большого количества цифр'),
]

# Список известных фишинговых доменов верхнего уровня
SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'click', 'download']

# Список сервисов сокращения ссылок
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link', 'ow.ly', 'buff.ly',
                  'is.gd', 'v.gd', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc']


def extract_domain_without_tld(domain):
    """Извлекает домен БЕЗ TLD для сравнения с базой данных
    Например: google.com -> google, mail.google.com -> google, yandex.ru -> yandex
    """
    # Убираем порт если есть
    domain = domain.split(':')[0]

    parts = domain.split('.')
    if len(parts) >= 2:
        # Берем предпоследнюю часть (домен без TLD и поддомена)
        # Например: mail.google.com -> google, google.com -> google
        return parts[-2]
    elif len(parts) == 1:
        # Если только одна часть, возвращаем её (уже без TLD)
        return parts[0]
    return domain


def check_url_safety(url):
    """Расширенная проверка URL на подозрительность"""
    original_url = url
    if not url or not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain_without_tld = extract_domain_without_tld(domain)
        path = parsed.path.lower()
        query = parsed.query.lower()

        results = {
            'url': url,
            'domain': domain,
            'base_domain': domain_without_tld,
            'is_safe': True,
            'warnings': [],
            'checks': {},
            'risk_score': 0,
            'recommendations': []
        }

        risk_score = 0

        # ПРОВЕРКА 1: Проверка в базе данных безопасных доменов
        # В базе домены хранятся БЕЗ TLD, поэтому сравниваем domain_without_tld
        is_in_database = domain_without_tld in SAFE_DOMAINS_SET
        results['checks']['in_safe_database'] = is_in_database
        if is_in_database:
            results['recommendations'].append('✅ Домен найден в базе данных безопасных доменов')
        else:
            risk_score += 30
            results['warnings'].append('⚠️ Домен не найден в базе данных безопасных доменов (15 миллионов доменов)')

        # ПРОВЕРКА 2: Подозрительные паттерны
        for pattern, description in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                risk_score += 25
                results['warnings'].append(f'🚨 {description}')
                results['checks']['suspicious_pattern'] = True

        # ПРОВЕРКА 3: HTTPS
        has_https = url.startswith('https://')
        results['checks']['has_https'] = has_https
        if not has_https:
            risk_score += 20
            results['warnings'].append('🔒 Отсутствует HTTPS шифрование - данные передаются в открытом виде')
            results['recommendations'].append('Используйте HTTPS для безопасного соединения')
        else:
            results['recommendations'].append('✅ Используется защищенное HTTPS соединение')

        # ПРОВЕРКА 4: Количество поддоменов
        domain_parts = domain.split('.')
        subdomain_count = len(domain_parts) - 2 if len(domain_parts) >= 2 else 0
        results['checks']['subdomain_count'] = subdomain_count
        if subdomain_count > 3:
            risk_score += 15
            results['warnings'].append(
                f'🔍 Обнаружено {subdomain_count} поддоменов - часто используется в фишинге для имитации легитимных сайтов')
        elif subdomain_count > 1:
            risk_score += 5

        # ПРОВЕРКА 5: Сокращенные ссылки
        is_shortener = any(shorter in domain for shorter in URL_SHORTENERS)
        results['checks']['is_shortener'] = is_shortener
        if is_shortener:
            risk_score += 30
            results['warnings'].append(
                '🔗 Использован сервис сокращения ссылок - невозможно проверить конечный адрес без перехода')
            results['recommendations'].append('Рекомендуется избегать сокращенных ссылок от незнакомых отправителей')

        # ПРОВЕРКА 6: IP адрес вместо домена
        ip_pattern = r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
        domain_without_port = domain.split(':')[0]
        if re.match(ip_pattern, domain_without_port):
            risk_score += 40
            results['warnings'].append(
                '🌐 Используется IP-адрес вместо домена - очень подозрительно, часто используется для обхода блокировок')
            results['checks']['is_ip_address'] = True

        # ПРОВЕРКА 7: Подозрительный TLD
        tld = domain_parts[-1] if domain_parts else ''
        if tld in SUSPICIOUS_TLDS:
            risk_score += 20
            results['warnings'].append(
                f'🏷 Используется подозрительный домен верхнего уровня (.{tld}) - часто используется для фишинга')
            results['checks']['suspicious_tld'] = True

        # ПРОВЕРКА 8: Длина домена
        domain_length = len(domain)
        results['checks']['domain_length'] = domain_length
        if domain_length > 50:
            risk_score += 15
            results['warnings'].append(
                f'📏 Очень длинный домен ({domain_length} символов) - может быть попыткой скрыть реальный адрес')
        elif domain_length > 30:
            risk_score += 5

        # ПРОВЕРКА 9: Подозрительные слова в пути
        phishing_keywords = ['login', 'signin', 'verify', 'confirm', 'update', 'secure', 'account', 'password', 'reset']
        suspicious_path = any(keyword in path for keyword in phishing_keywords)
        if suspicious_path and not is_in_database:
            risk_score += 15
            results['warnings'].append('📝 URL содержит подозрительные слова (login, verify и т.д.) - может быть фишингом')

    # ПРОВЕРКА 10: Кодирование URL
        if '%' in url:
            risk_score += 10
            results['warnings'].append('🔤 URL содержит закодированные символы - может скрывать подозрительный контент')

    # ПРОВЕРКА 11: Одинаковые символы (возможная опечатка в домене известного бренда)
        common_typos = ['g00gle', 'faceb00k', 'y0utube', 'amaz0n', 'micr0soft']
        for typo in common_typos:
            if typo in domain:
                risk_score += 35
                results['warnings'].append(f'✏️ Обнаружена возможная опечатка в домене ({typo}) - может быть фишингом')

    # ПРОВЕРКА 12: Длина пути
        if len(path) > 100:
            risk_score += 10
            results['warnings'].append('📄 Очень длинный путь в URL - может содержать скрытые параметры')

    # Определение итогового статуса
        results['risk_score'] = min(risk_score, 100)

        if risk_score >= 70:
            results['is_safe'] = False
        elif risk_score >= 40:
            results['is_safe'] = None  # Неопределенно
        else:
            results['is_safe'] = True

    # Дополнительные рекомендации
        if results['is_safe'] == False:
            results['recommendations'].append('🚫 НЕ РЕКОМЕНДУЕТСЯ переходить по этой ссылке')
        elif results['is_safe'] == None:
            results['recommendations'].append('⚠️ Будьте осторожны при переходе по этой ссылке')
        else:
            results['recommendations'].append('✅ Ссылка выглядит безопасной, но всегда будьте осторожны')

        return results

    except Exception as e:
        return {
            'url': original_url,
            'error': str(e),
            'is_safe': None,
            'risk_score': 0
    }


@app.route('/')
def index():
    domain_count = len(SAFE_DOMAINS_SET)
    domain_count_formatted = f"{domain_count:,}"
    domain_count_millions = f"{domain_count / 1000000:.1f}M"
    return render_template('index.html',
                           domain_count=domain_count,
                           domain_count_formatted=domain_count_formatted,
                           domain_count_millions=domain_count_millions)


@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL не указан'}), 400

    result = check_url_safety(url)
    return jsonify(result)


if __name__ == 'main':
    print("=" * 60)
    print("🛡  СЕРВЕР ПРОВЕРКИ ССЫЛОК НА БЕЗОПАСНОСТЬ")
    print("=" * 60)
    print(f"📊 База данных: {len(SAFE_DOMAINS_SET)} безопасных доменов")
    print("🚀 Сервер запущен на http://localhost:5000")
    print("📋 Откройте браузер и перейдите по адресу выше")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)