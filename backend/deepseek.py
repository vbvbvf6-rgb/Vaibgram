from enum import Enum
from typing import List, Tuple

class ThreatLevel(str, Enum):
    SAFE = "safe"
    WARNING = "warning"
    CRITICAL = "critical"

FRAUD_KEYWORDS = {
    "ru": [
        "выиграл", "выигрыш", "приз", "бесплатные деньги", "подтвердите платеж",
        "срочно", "нажмите здесь", "проверьте аккаунт", "обновите данные", "пароль",
        "банк просит", "отправьте деньги", "переводы", "кредит", "инвестиция",
        "миракль", "похудеть за день"
    ],
    "en": [
        "confirm payment", "urgent action", "click here", "verify account",
        "update information", "password", "prize money", "free money",
        "send money", "wire transfer", "bitcoin", "gift card", "investment",
        "loan", "credit", "fast money"
    ]
}

SCAM_KEYWORDS = {
    "ru": [
        "подарок", "акция", "бонус", "скидка", "платеж", "кошелек", "mir", "сбер", "заполните",
        "кошелёк", "данные", "карту", "счет", "сбербанк", "транзакцию"
    ],
    "en": [
        "gift", "bonus", "discount", "payment", "wallet", "account", "card",
        "transaction", "verify", "details", "bank", "checkout"
    ]
}

VIOLENCE_KEYWORDS = {
    "ru": ["бомб", "взрыв", "терракт", "убий", "оружие", "взорви", "разрушить", "напасть"],
    "en": ["bomb", "explosion", "attack", "kill", "weapon", "destroy", "terror"]
}

def _normalize_text(value: str) -> str:
    if not value:
        return ""
    return " ".join(value.lower().split())


def analyze_message(content: str, language: str = "ru") -> Tuple[ThreatLevel, List[str], float]:
    text = _normalize_text(content)
    if not text:
        return ThreatLevel.SAFE, [], 0.0

    fraud_list = FRAUD_KEYWORDS.get(language, FRAUD_KEYWORDS["en"])
    scam_list = SCAM_KEYWORDS.get(language, SCAM_KEYWORDS["en"])
    violence_list = VIOLENCE_KEYWORDS.get(language, VIOLENCE_KEYWORDS["en"])

    detected: List[str] = []
    score = 0.0

    for keyword in fraud_list + scam_list:
        if keyword in text:
            detected.append(f"scam:{keyword}")
            score += 0.18

    for keyword in violence_list:
        if keyword in text:
            detected.append(f"violence:{keyword}")
            score += 0.27

    if "send money" in text or "отправьте деньги" in text:
        score += 0.15
    if "confirm" in text and "payment" in text:
        score += 0.12

    if score >= 0.55:
        level = ThreatLevel.CRITICAL
    elif score >= 0.28:
        level = ThreatLevel.WARNING
    else:
        level = ThreatLevel.SAFE

    confidence = min(score, 1.0)
    return level, detected, confidence
