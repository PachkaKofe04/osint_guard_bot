# utils/telegram_io.py
"""
Безопасная отправка сообщений в Telegram.

Решает три проблемы, из-за которых пользователь молча не получал ответ:
  1. Лимит 4096 символов — длинные отчёты (домен с большим SAN-списком)
     отвергались с "message is too long".
  2. Сломанная HTML-разметка — если в данные просочился неэкранированный
     символ, Telegram отвечает "can't parse entities" и сообщение теряется.
  3. "message is not modified" при повторном нажатии той же кнопки.

Все хендлеры отправляют результаты через эти функции, а не напрямую.
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from aiogram.exceptions import TelegramBadRequest
from aiogram.types import Message

from utils.safe_html import strip_tags

log = logging.getLogger(__name__)

# Telegram отвергает сообщения длиннее 4096 символов.
# Берём с запасом — суффикс «часть N» тоже занимает место.
TELEGRAM_MAX_LEN = 4096
SAFE_CHUNK_LEN = 3900


def split_text(text: str, limit: int = SAFE_CHUNK_LEN) -> List[str]:
    """
    Режет текст на части не длиннее limit, стараясь рвать по границам строк.

    Строка длиннее limit (например, огромный robots.txt одной строкой)
    режется жёстко по символам — иначе она не пролезет вообще.
    """
    if len(text) <= limit:
        return [text]

    chunks: List[str] = []
    current = ""

    for line in text.split("\n"):
        # Сама строка не влезает в лимит — рубим её на куски
        while len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]

        candidate = line if not current else current + "\n" + line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate

    if current:
        chunks.append(current)

    return chunks or [""]


def _is_parse_error(exc: TelegramBadRequest) -> bool:
    return "can't parse entities" in str(exc).lower()


def _is_not_modified(exc: TelegramBadRequest) -> bool:
    return "message is not modified" in str(exc).lower()


def _is_too_long(exc: TelegramBadRequest) -> bool:
    text = str(exc).lower()
    return "message is too long" in text or "text is too long" in text


async def safe_answer(
    message: Message,
    text: str,
    reply_markup: Optional[Any] = None,
    **kwargs: Any,
) -> Optional[Message]:
    """
    Отправляет текст, разбивая на части при необходимости.
    reply_markup прикрепляется к последней части — чтобы кнопки были под концом отчёта.
    Возвращает последнее отправленное сообщение.
    """
    chunks = split_text(text)
    sent: Optional[Message] = None

    for i, chunk in enumerate(chunks):
        is_last = i == len(chunks) - 1
        markup = reply_markup if is_last else None
        try:
            sent = await message.answer(chunk, reply_markup=markup, **kwargs)
        except TelegramBadRequest as exc:
            if _is_parse_error(exc):
                log.warning("[telegram_io] Разметка отвергнута, откат на plain text: %s", exc)
                sent = await message.answer(
                    strip_tags(chunk), reply_markup=markup,
                    **{**kwargs, "parse_mode": None},
                )
            elif _is_too_long(exc):
                # Подстраховка: режем ещё мельче
                log.warning("[telegram_io] Часть всё ещё длинна, дробим: %s", exc)
                for sub in split_text(chunk, SAFE_CHUNK_LEN // 2):
                    sent = await message.answer(sub, **kwargs)
                if markup is not None and sent is not None:
                    sent = await message.answer("⬇️", reply_markup=markup)
            else:
                raise

    return sent


async def safe_edit(
    message: Message,
    text: str,
    reply_markup: Optional[Any] = None,
    **kwargs: Any,
) -> Optional[Message]:
    """
    Редактирует сообщение. Если текст не влезает — первая часть уходит в edit,
    остальные отправляются следом отдельными сообщениями.

    "message is not modified" не считается ошибкой: пользователь просто
    нажал ту же кнопку ещё раз.
    """
    chunks = split_text(text)
    head, tail = chunks[0], chunks[1:]
    head_markup = reply_markup if not tail else None

    try:
        await message.edit_text(head, reply_markup=head_markup, **kwargs)
    except TelegramBadRequest as exc:
        if _is_not_modified(exc):
            log.debug("[telegram_io] Сообщение не изменилось — пропускаем")
        elif _is_parse_error(exc):
            log.warning("[telegram_io] Разметка отвергнута при edit, откат на plain text: %s", exc)
            await message.edit_text(
                strip_tags(head), reply_markup=head_markup,
                **{**kwargs, "parse_mode": None},
            )
        else:
            raise

    sent: Optional[Message] = message
    for i, chunk in enumerate(tail):
        is_last = i == len(tail) - 1
        sent = await safe_answer(
            message, chunk,
            reply_markup=reply_markup if is_last else None,
            **kwargs,
        )

    return sent
