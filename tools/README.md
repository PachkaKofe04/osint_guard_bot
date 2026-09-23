# tools/ - инструменты аудита

Не часть бота. Используются для проверки его состояния.

## wiring_probe.py
Прогоняет синтетические Telegram-апдейты через **настоящий** `Dispatcher`
с мок-ботом (ни одного реального запроса к Telegram). Показывает, какой
хендлер и чем ответил на каждый ввод.

```bash
PYTHONPATH=. PYTHONIOENCODING=utf-8 ./.venv/Scripts/python.exe tools/wiring_probe.py
NO_RL=1 PYTHONPATH=. PYTHONIOENCODING=utf-8 ./.venv/Scripts/python.exe tools/wiring_probe.py   # без rate limiter
```

Ищем в выводе: `∅ НЕТ ОТВЕТА` (бот молчит), `⏱ Слишком много запросов`
на кнопках (баг rate limiter), `💥` (исключение), `⏱ TIMEOUT`.

## api_health.py
Параллельно проверяет живость всех внешних источников данных.

```bash
PYTHONIOENCODING=utf-8 ./.venv/Scripts/python.exe tools/api_health.py
```

Легенда: `OK` - 200 · `AUTH` - нужен ключ · `LIMIT` - 429 · `FAIL` - иной код · `DEAD` - не отвечает.
