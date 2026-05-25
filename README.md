<p align="center">
  <i>«Маяк у гаснущего горизонта свободного интернета»</i><br>
  Форк <a href="https://github.com/Runnin4ik/dpi-detector"><b>Runni/dpi-detector</b></a> с упором на AI-сервисы и интеграцию с zapret2.
</p>

# 🔍 Full DPI Checker

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Upstream](https://img.shields.io/badge/upstream-Runnin4ik%2Fdpi--detector-lightgrey)](https://github.com/Runnin4ik/dpi-detector)

Инструмент для анализа цензуры трафика — обнаруживает и классифицирует блокировки сайтов, AI-сервисов, хостингов и CDN (TCP 16-20KB), подмену DNS-запросов провайдером, **и автоматически предлагает обходные стратегии через [zapret2](https://github.com/bol-van/zapret2)**.

> <b>Инструмент был полезен? Поставь ⭐ в качестве «спасибо»!</b>

## 🆕 Что добавил форк

| Фича | Описание |
|---|---|
| **🤖 Тест 8 — AI/LLM сервисы** | Куратированный список из ~70 нейросетей: Claude, ChatGPT, Gemini, Copilot, Grok, DeepSeek, Mistral, Cohere, Perplexity, Cursor, OpenRouter, HuggingFace, Replicate, ElevenLabs, Midjourney и др. |
| **🛡️ zapret2 suggester** | После обнаружения блоков выводит конкретные команды для bypass-проверки с 5 готовыми DPI-стратегиями (split2, fakedsplit, disorder2, multidisorder и др.) |
| **📜 `--gen-zapret`** | Генерирует `zapret2_test.bat` (Windows) или `zapret2_test.sh` (Linux), который перебирает стратегии против заблокированных доменов |
| **🎯 IP-vs-DPI классификация** | Разделяет блоки на bypassable через zapret2 vs IP-level (требуют VPN) — не тратит время на безнадёжные стратегии |

## 🎯 Все возможности

- **🤖 AI/LLM проверка** (новое) — все основные нейросетевые сервисы одной командой
- **🛡️ zapret2 интеграция** (новое) — после теста: классификация + готовые bypass-команды + генератор скрипта
- **TCP 16-20KB блокировка** — обрыв соединения после 14-34KB (типично для CDN)
- **Подбор белых SNI для AS хостингов/CDN**
- **Проверка доступности сайтов** — TLS 1.2, TLS 1.3, HTTP
- **Проверка DNS** — UDP/53 перехват, IP-подмена, блокировка DoH
- **Классификация ошибок** — TCP RST, Abort, Handshake/Read Timeout, TLS MITM, SNI-блок
- **Telegram замедление/блокировка**
- **Гибкая настройка** — таймауты, потоки, свои списки доменов

> [!WARNING]
> Если у вас запущены средства обхода блокировок (zapret/GoodbyeDPI), результаты будут искажены. Выключите их или переведите в режим ALL.

## 🚀 Быстрый старт

```bash
# Установка
git clone https://github.com/lildebil0/full-dpi-checker.git
cd full-dpi-checker
python -m pip install -r requirements.txt

# Запуск меню
python dpi_detector.py

# Только AI-сервисы
python dpi_detector.py -t 8

# DNS + AI + сразу сгенерировать zapret2 тестер
python dpi_detector.py -t 18 --gen-zapret

# Через прокси (если основной канал блокирует)
python dpi_detector.py -t 8 -p socks5://127.0.0.1:1080
```

## 🤖 Тест 8 — что внутри `domains_ai.txt`

| Категория | Примеры |
|---|---|
| **LLM chat** | Claude, ChatGPT, Gemini, Copilot, Grok, DeepSeek, Mistral, Cohere, Perplexity |
| **AI-coding** | Cursor, Windsurf, Codeium, GitHub Copilot |
| **Inference providers** | OpenRouter, Groq, Together, Fireworks, Replicate |
| **Open hubs** | HuggingFace, Ollama, ModelScope |
| **Image/video/voice** | Midjourney, Runway, Stability, ElevenLabs, Deepgram |
| **Vector DBs** | Pinecone, Qdrant, Weaviate |

Редактируй `domains_ai.txt` чтобы добавить свои сервисы — формат как у обычного `domains.txt`.

## 🛡️ zapret2 интеграция — как работает

После теста, если найдены блокировки:

1. **Классификация:** скрипт разделяет блокированные домены на 2 группы:
   - 🟢 **zapret2-bypassable** — TLS DPI, SNI block, TCP RST mid-stream, 16-20KB drop
   - 🔴 **IP-level** — TCP TIMEOUT к direct IP, DNS-hijack — нужен VPN, zapret2 не поможет
2. **Предложение стратегий:** показывает 5 winws.exe / nfqws команд от простой к агрессивной:
   - `split2-md5sig` — простейший
   - `fake-split2-ttl` — против active probe DPI
   - `fakedsplit` — против strict SNI-парсера
   - `disorder2-md5sig` — обходит TCP-reassembly DPI
   - `multidisorder-badseq` — самый агрессивный
3. **Генерация тестера** (`--gen-zapret`): создаёт `zapret2_test.bat` (Windows) или `zapret2_test.sh` (Linux), который автоматически перебирает все 5 стратегий против заблокированных доменов.

**Использование сгенерированного скрипта:**

```bash
# 1. Скачай zapret2: https://github.com/bol-van/zapret2/releases/latest
# 2. Положи winws.exe (Windows) или nfqws (Linux) рядом со скриптом
# 3. Запусти
./zapret2_test.sh    # Linux (с sudo для nfqws + iptables)
zapret2_test.bat     # Windows (Admin)
```

В соседнем терминале проверяй: `curl -v https://api.anthropic.com` — какая стратегия позволила connect-нуться без RST, та и работает у твоего провайдера.

## ⚙️ Кастомизация

Файлы можно переопределить, положив свою версию рядом с программой:

1. `domains.txt` — обычные домены (тест 3)
2. `domains_ai.txt` — **AI-сервисы (тест 8, новое)**
3. `tcp16.json` — цели для TCP 16-20KB
4. `whitelist_sni.txt` — белые SNI
5. `config.yml` — таймауты, MAX_CONCURRENT, прокси

## 📋 Меню тестов

```
1  — Подмена DNS
2  — Доступность DNS-серверов
3  — Доступность обычных доменов
4  — TCP 16-20KB блокировка
5  — Белые SNI для ASN
6  — Telegram (замедление/блокировка)
7  — Легенда статусов
8  — AI/LLM сервисы (Claude/ChatGPT/Gemini/Copilot/Grok/DeepSeek/...)
```

Можно комбинировать: `-t 138` = DNS + домены + AI.

## 🔗 Связанные проекты

- [bol-van/zapret2](https://github.com/bol-van/zapret2) — DPI bypass tool, для которого этот checker генерирует стратегии
- [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) — оригинальный upstream
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) — альтернативный bypass-tool

## 📄 Лицензия

MIT (наследовано от upstream).

---

<p align="center">
  <sub>Fork by <a href="https://github.com/lildebil0">lildebil0</a> · Upstream by <a href="https://github.com/Runnin4ik">Runni</a></sub>
</p>
