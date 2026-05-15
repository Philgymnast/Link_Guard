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
