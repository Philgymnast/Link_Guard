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
