# email_scanner/disposable.py
"""Список одноразовых email доменов."""

# Популярные одноразовые email сервисы
DISPOSABLE_DOMAINS = {
    # Популярные
    "tempmail.com", "temp-mail.org", "temp-mail.ru",
    "guerrillamail.com", "guerrillamail.org", "guerrillamail.net",
    "10minutemail.com", "10minutemail.net",
    "mailinator.com", "mailinator.net",
    "throwaway.email", "throwawaymail.com",
    "fakeinbox.com", "fakemailgenerator.com",
    "getnada.com", "tempail.com",
    "dispostable.com", "mailnesia.com",
    "maildrop.cc", "mailsac.com",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "sharklasers.com", "spam4.me",
    "trashmail.com", "trashmail.net", "trashmail.org",
    "mintemail.com", "tempinbox.com",
    "mohmal.com", "emailondeck.com",

    # Русскоязычные
    "dropmail.me", "mailforspam.com",
    "trash-mail.com", "wegwerfmail.de",
    "spamgourmet.com", "spambox.us",

    # Новые
    "tmpmail.org", "tmpmail.net",
    "emailfake.com", "emkei.cz",
    "fakemailgenerator.net", "fakemail.net",
    "getairmail.com", "mailcatch.com",
    "mytrashmail.com", "nowmymail.com",
    "throwam.com", "zmail.wiki",

    # Прочие
    "33mail.com", "abyssmail.com",
    "anonymbox.com", "antispam.de",
    "binkmail.com", "bobmail.info",
    "bofthew.com", "boun.cr",
    "bouncr.com", "bugmenot.com",
    "bumpymail.com", "burnthespam.info",
    "buyusedlibrarybooks.org", "byom.de",
    "cachedot.net", "casualdx.com",
    "centermail.com", "cheatmail.de",
    "consumerriot.com", "cool.fr.nf",
    "correo.blogos.net", "cosmorph.com",
    "courriel.fr.nf", "courrieltemporaire.com",
    "curryworld.de", "cust.in",
    "dacoolest.com", "dandikmail.com",
    "deadaddress.com", "despam.it",
    "despammed.com", "devnullmail.com",
    "dfgh.net", "digitalsanctuary.com",
    "discardmail.com", "discardmail.de",
    "disposableaddress.com", "disposeamail.com",
    "disposemail.com", "dispostable.com",
    "dm.w3internet.co.uk", "dodgeit.com",
    "dodgit.com", "dodgit.org",
    "dontreg.com", "dontsendmespam.de",
    "drdrb.com", "dump-email.info",
    "dumpandjunk.com", "dumpmail.de",
    "dumpyemail.com", "e4ward.com",
    "easytrashmail.com", "einmalmail.de",
    "email60.com", "emaildienst.de",
    "emailias.com", "emailigo.de",
    "emailinfive.com", "emaillime.com",
    "emailmiser.com", "emailsensei.com",
    "emailtemporanea.com", "emailtemporanea.net",
    "emailtemporar.ro", "emailwarden.com",
    "emailx.at.hm", "emailxfer.com",
    "emz.net", "enterto.com",
    "ephemail.net", "etranquil.com",
    "etranquil.net", "etranquil.org",
    "evopo.com", "explodemail.com",
    "fakeinbox.net", "fakeinformation.com",
    "fastacura.com", "fastchevy.com",
    "fastchrysler.com", "fastkawasaki.com",
    "fastmazda.com", "fastmitsubishi.com",
    "fastnissan.com", "fastsubaru.com",
    "fastsuzuki.com", "fasttoyota.com",
    "fastyamaha.com", "filzmail.com",
    "fizmail.com", "flyspam.com",
    "fr33mail.info", "frapmail.com",
    "friendlymail.co.uk", "fuckingduh.com",
    "fudgerub.com", "garliclife.com",
    "gehensiull.com", "gelitik.in",
    "ghosttexter.de", "gishpuppy.com",
    "goemailgo.com", "gorillaswithdirtyarmpits.com",
    "gotmail.net", "gotmail.org",
    "gowikibooks.com", "gowikicampus.com",
    "gowikicars.com", "gowikifilms.com",
}

# Бесплатные email провайдеры (не одноразовые, но бесплатные)
FREE_EMAIL_PROVIDERS = {
    # Основные
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",

    # Российские
    "mail.ru", "bk.ru", "inbox.ru", "list.ru",
    "yandex.ru", "yandex.com", "ya.ru",
    "rambler.ru",

    # Прочие
    "aol.com", "protonmail.com", "proton.me",
    "zoho.com", "gmx.com", "gmx.de",
    "tutanota.com", "tutamail.com",
    "mail.com", "email.com",
}


def is_disposable_email(domain: str) -> bool:
    """Проверяет, является ли домен одноразовым email сервисом."""
    domain = domain.lower().strip()
    return domain in DISPOSABLE_DOMAINS


def is_free_provider(domain: str) -> bool:
    """Проверяет, является ли домен бесплатным email провайдером."""
    domain = domain.lower().strip()
    return domain in FREE_EMAIL_PROVIDERS


def get_provider_name(domain: str) -> str:
    """Возвращает название провайдера по домену."""
    domain = domain.lower().strip()

    provider_map = {
        "gmail.com": "Google Gmail",
        "googlemail.com": "Google Gmail",
        "yahoo.com": "Yahoo Mail",
        "outlook.com": "Microsoft Outlook",
        "hotmail.com": "Microsoft Hotmail",
        "live.com": "Microsoft Live",
        "icloud.com": "Apple iCloud",
        "mail.ru": "Mail.ru",
        "yandex.ru": "Яндекс Почта",
        "yandex.com": "Yandex Mail",
        "protonmail.com": "ProtonMail",
        "proton.me": "Proton Mail",
    }

    if domain in provider_map:
        return provider_map[domain]

    if is_disposable_email(domain):
        return "Одноразовый email"

    return ""
