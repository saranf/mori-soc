"""개인정보 처리흐름표/흐름도 서비스 — ISMS-P 3.x 증적.

MORI 는 코드를 읽지 않는다("증적 층"). 스캔(고객 CI Semgrep)이 보낸 findings 중
PII/secret 성격을 골라 흐름표 "후보 행"으로 시드하고, 담당자가 저장위치·목적·
보관·파기를 채운다. 흐름표는 수집→저장→이용→파기 흐름도(SVG)로 렌더되고 3.x
통제 증적으로 승격된다. 이 모듈은 순수 함수만 담는다(저장은 state_repo).
"""
from __future__ import annotations

import html
import re
from typing import Any

# 개인정보 처리 단계(흐름도 열 순서) — ISMS-P 3.1 수집 → 저장 → 3.2 이용/제공 → 3.4 파기.
STAGES = ("수집", "저장", "이용", "파기")

# 흐름표 한 행의 필드(빈 값 허용 — 담당자가 점진적으로 채움).
FLOW_FIELDS = (
    "item", "category", "subject", "collection_source", "storage_location", "storage_table",
    "storage_column", "encryption", "purpose", "retention", "destruction", "third_party", "overseas", "note",
)

# 우려사항 → ISMS-P 통제 ID(카탈로그 실재 ID). 레퍼런스 상세도의 '붉은 우려사항' 매핑.
CONCERN_CONTROLS = {"enc": "2.7.1", "third_party": "3.3.1", "overseas": "3.3.4", "dispose": "3.4.1"}
_SENSITIVE_CATS = ("고유식별정보", "금융정보", "민감정보")

# 저장 암호화 표식 — 알고리즘/힌트 탐지(코드 근거 기반, 없으면 '미확인'으로 두고 단정 안 함).
_ENC_ALGO = re.compile(
    r"(?i)\b(aes[-_]?\d{0,3}(?:[-_]?(?:gcm|cbc|ctr))?|rsa|chacha20|argon2(?:id)?|bcrypt|scrypt|pbkdf2|"
    r"sha-?(?:256|512))\b")
_ENC_HINT = re.compile(r"(?i)(encrypt|cipher|암호화|blind[\s_-]?index|[a-z]+enc\b|[a-z]+hash\b|hashed)")

# 서비스 시크릿(API키·토큰·자격증명)은 정보주체의 "개인정보"가 아니다 → 흐름표에서 제외.
# (보안 findings 로는 code_review 가 별도로 잡는다.) 개인정보 vs secret 을 명확히 분리.
_SECRET_SIGNAL = re.compile(
    r"\b(secret|credential|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|bearer|aws[_-]?(access|secret)|jwt[_-]?secret)\b",
    re.IGNORECASE,
)

# 개인정보 항목 사전: (단어경계 정규식, 항목 라벨, 민감도 구분). 단어경계로 부분문자열
# 오탐(monkey→key, discard→card, headphone→phone, IP address→주소)을 막는다.
# 구분(category): 고유식별정보 > 금융정보 > 민감정보 > 일반개인정보 (민감도 우선순위).
_PII_ITEMS: tuple[tuple[str, str, str], ...] = (
    (r"(?i)\b(resident_?reg(_?num)?|residentnumber|rrn|ssn|jumin)\b|주민등록번호|주민번호", "주민등록번호", "고유식별정보"),
    (r"(?i)\bpassport(_?(no|number))?\b|여권번호|여권", "여권번호", "고유식별정보"),
    (r"(?i)\b(driver_?license|license_?no|driving_?license)\b|운전면허(번호)?", "운전면허번호", "고유식별정보"),
    (r"(?i)\b(card_?(number|no)|creditcard|pan)\b|카드번호|신용카드", "카드번호", "금융정보"),
    (r"(?i)\b(account_?(number|no)|bank_?account|iban)\b|계좌번호", "계좌번호", "금융정보"),
    (r"(?i)\b(health|medical|diagnosis|disease|prescription)\b|건강정보|질병|진료|처방", "건강정보", "민감정보"),
    (r"(?i)\b(religion|political|ideology)\b|종교|정치성향|사상", "사상·신념", "민감정보"),
    (r"(?i)\bemail(_?address)?\b|이메일|메일주소", "이메일", "일반개인정보"),
    (r"(?i)\b(phone|mobile|tel|telephone|msisdn|cellphone)\b|휴대폰|전화번호|연락처", "전화번호", "일반개인정보"),
    (r"(?i)\b(birth_?date|birthday|birthdate|dob)\b|생년월일|생일", "생년월일", "일반개인정보"),
    (r"(?i)\bgender\b|성별", "성별", "일반개인정보"),
    (r"(?i)(?<!ip )(?<!mac )(?<!web )(?<!url )\b(home_?address|street_?address|shipping_?address|road_?address|postal_?address)\b|(?<![a-z])주소|배송지", "주소", "일반개인정보"),
    (r"(?i)\b(full_?name|first_?name|last_?name)\b|성명|고객명|성함", "이름", "일반개인정보"),
)
_CATEGORY_RANK = {"고유식별정보": 4, "금융정보": 3, "민감정보": 2, "일반개인정보": 1, "": 0}
_PII_ITEMS_C = tuple((re.compile(rx), label, cat) for rx, label, cat in _PII_ITEMS)
# 개인정보 신호 = 항목 사전 중 하나라도 매칭되거나, 명시적 개인정보 카테고리 rule.
_PII_SIGNAL = re.compile(r"(?i)\b(pii|personal[_-]?data|personal[_-]?info|privacy|gdpr)\b|개인정보")

# 어드민이 러프하게 늘릴 수 있는 PII 필드 기본셋 — (semgrep pattern-regex, 항목 라벨).
# 스캔이 리터럴 값뿐 아니라 필드/스키마 식별자까지 잡도록(이름·성별·생년월일·주소 등).
DEFAULT_PII_FIELDS: tuple[tuple[str, str], ...] = (
    (r"(?i)\bemail\b|이메일", "이메일"),
    (r"(?i)\b(phone|mobile|tel)\b|휴대폰|전화번호", "전화번호"),
    (r"(?i)\b(resident_?reg_?num|residentnumber|rrn|ssn|jumin)\b|주민등록번호", "주민등록번호"),
    (r"(?i)\b(card_?number|creditcard)\b|카드번호", "카드번호"),
    (r"(?i)\b(account_?number|bank_?account)\b|계좌번호", "계좌번호"),
    (r"(?i)\b(birth_?date|birthday|dob)\b|생년월일", "생년월일"),
    (r"(?i)\bgender\b|성별", "성별"),
    (r"(?i)\b(address|shipping_?address)\b|주소|배송지", "주소"),
    (r"(?i)\bpassport\b|여권", "여권번호"),
    (r"(?i)\b(full_?name)\b|성명|고객명", "이름"),
)


def _pii_hay(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(k) or "") for k in
                    ("rule_id", "ruleId", "category", "rule", "title", "message", "description", "snippet"))


def _matched_items(finding: dict[str, Any]) -> list[tuple[str, str]]:
    """finding 에서 매칭된 (항목 라벨, 구분) 리스트 — 단어경계 기준."""
    hay = _pii_hay(finding)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for pat, label, cat in _PII_ITEMS_C:
        if pat.search(hay) and label not in seen:
            seen.add(label)
            out.append((label, cat))
    return out


def is_pii_finding(finding: dict[str, Any]) -> bool:
    """finding 이 (서비스 시크릿이 아닌) 개인정보 관련인지. secret 은 흐름표에서 제외."""
    hay = _pii_hay(finding)
    items = _matched_items(finding)
    # 구체 항목이 잡히면 개인정보로 확정(시크릿 신호가 있어도 이메일/카드 등은 개인정보).
    if items:
        return True
    # 항목은 못 잡았지만 명시적 개인정보 rule 이고, 순수 시크릿 신호가 아니면 포함.
    return bool(_PII_SIGNAL.search(hay)) and not _SECRET_SIGNAL.search(hay)


def infer_item(finding: dict[str, Any]) -> str:
    """finding 에서 개인정보 항목을 추론(없으면 빈 문자열). 단어경계로 오탐 최소화."""
    return ", ".join(label for label, _ in _matched_items(finding)[:3])


def infer_category(finding: dict[str, Any]) -> str:
    """매칭된 항목 중 가장 민감한 구분(고유식별>금융>민감>일반)을 반환. 없으면 빈 문자열."""
    cats = [cat for _, cat in _matched_items(finding)]
    return max(cats, key=lambda c: _CATEGORY_RANK.get(c, 0), default="")


# 파일 경로로 개인정보 처리 단계를 추정 — MORI 는 코드를 안 읽으니 경로 단서로 best-effort.
_COLLECT_HINTS = ("signup", "sign-up", "sign_up", "register", "registration", "join", "login",
                  "sign-in", "signin", "/form", "checkout", "contact", "subscribe", "apply",
                  "onboard", "survey", "profile", "mypage", "account", "input", "enroll", "order")
_STORE_HINTS = ("seed", "migration", "migrate", "schema", "prisma", "/model", "entity", "repository",
                "dao", ".sql", "/db/", "database", "fixtures", "/store", "insert")
_USE_HINTS = ("/api/", "route", "handler", "service", "controller", "usecase", "use-case", "process",
              "send", "mailer", "sms", "notif", "export", "report", "analytic", "payment", "/lib/")
_DISPOSE_HINTS = ("erase", "/destroy", "purge", "withdraw", "탈퇴", "파기", "deletion", "expire")


# 스니펫/메시지에서 DB 테이블·모델명을 뽑는다 — Prisma·SQL·TypeORM·Sequelize 흔한 패턴.
_TABLE_PATTERNS = (
    re.compile(r"\bmodel\s+([A-Za-z_]\w*)", re.I),                 # Prisma: model User {
    re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?[\"'`\[]?([A-Za-z_]\w*)", re.I),  # SQL
    re.compile(r"@Entity\([^)]*\)\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_]\w*)", re.I),  # TypeORM
    re.compile(r"table\s*[:=]\s*[\"'`]([A-Za-z_]\w*)", re.I),      # sequelize/knex tableName
    re.compile(r"@Table\([^)]*name\s*[:=]\s*[\"'`]([A-Za-z_]\w*)", re.I),
)


# 스니펫/코드 근거가 담길 수 있는 키(무료 SARIF·유료 Claude 양쪽 형태 모두 커버).
_CODE_KEYS = ("snippet", "code", "lines", "context", "message", "description", "title")


def _code_hay(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for k in _CODE_KEYS:
        v = finding.get(k)
        if isinstance(v, (list, tuple)):
            v = " ".join(str(x) for x in v)
        elif isinstance(v, dict):  # SARIF snippet={"text": ...} 등
            v = str(v.get("text") or v.get("lines") or "")
        if v:
            parts.append(str(v))
    return " ".join(parts)


# 테이블/모델 정의 블록 추출(컬럼을 그 안에서만 찾기 위함).
_BLOCK_PATTERNS = (
    re.compile(r"model\s+[A-Za-z_]\w*\s*\{(.*?)\}", re.I | re.S),                     # Prisma
    re.compile(r"create\s+table[^(]*\((.*)\)\s*;?", re.I | re.S),                     # SQL (greedy: VARCHAR(n) 내부 괄호 대응)
    re.compile(r"@Entity\([^)]*\)\s*(?:export\s+)?(?:abstract\s+)?class\s+[A-Za-z_]\w*\s*\{(.*?)\}", re.I | re.S),  # TypeORM
)


def _table_block(hay: str) -> str:
    """model/CREATE TABLE/@Entity 정의의 본문(컬럼이 들어있는 부분)을 반환. 없으면 빈 문자열."""
    for pat in _BLOCK_PATTERNS:
        m = pat.search(hay)
        if m:
            return m.group(1)
    return ""


def infer_table(finding: dict[str, Any]) -> str:
    """finding 스니펫/메시지에서 DB 테이블(모델)명을 추정. 없으면 빈 문자열."""
    hay = _code_hay(finding)
    for pat in _TABLE_PATTERNS:
        m = pat.search(hay)
        if m:
            return m.group(1)
    return ""


def infer_columns(finding: dict[str, Any]) -> list[str]:
    """스니펫의 테이블/모델 블록에서 **개인정보 컬럼(필드)명**을 추출.

    ``_PII_ITEMS`` 패턴이 곧 컬럼 식별자(email·phone·rrn…)를 매칭하므로, 블록 안에서
    매칭된 토큰=실제 컬럼명이다. 테이블 블록이 없으면 스니펫 전체에서 찾는다(폴백).
    식별자형(영문/underscore) 토큰만 취해 한글 라벨·잡음은 제외한다.
    """
    hay = _code_hay(finding)
    if not hay:
        return []
    scope = _table_block(hay) or hay
    cols: list[str] = []
    seen: set[str] = set()
    for pat, _label, _cat in _PII_ITEMS_C:
        for m in pat.finditer(scope):
            tok = (m.group(0) or "").strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok) and tok.lower() not in seen:
                seen.add(tok.lower())
                cols.append(tok)
    return cols[:8]


def build_file_overview(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """흐름표 행들을 **파일(=테이블/업무) 단위**로 묶어 '개인정보 파일 개요' 표를 만든다.

    레퍼런스(ISMS-P 개인정보 파일 개요)의 열: 파일명 · 정보주체 수 · 개인정보 항목(필수/선택)
    · 제3자 제공 · 처리 목적. 항목·제3자·목적은 스캔/행에서 **자동 집계**하고, 정보주체 수와
    필수/선택 구분은 **담당자 입력**(행의 subject_count·requirement 필드)을 반영하되 비면 비워 둔다.

    필수/선택 미지정 행은 항목을 '필수'로 본다(개인정보는 기본 필수라는 보수적 가정 — 담당자가 조정).
    그룹 키: file_name > business > table > '(미분류)'.
    """
    def _clean(v: Any) -> str:
        return str(v or "").strip()

    def _real(v: str) -> bool:
        return bool(v) and v not in ("없음", "-", "n/a", "N/A")

    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for r in rows:
        key = _clean(r.get("file_name")) or _clean(r.get("business")) or _clean(r.get("table")) or "(미분류)"
        g = groups.get(key)
        if g is None:
            g = {"file_name": key, "required": [], "optional": [],
                 "third_party": [], "purposes": [], "subject_count": "", "tables": []}
            groups[key] = g
            order.append(key)
        item = _clean(r.get("item"))
        if item:
            bucket = "optional" if _clean(r.get("requirement")) == "선택" else "required"
            other = "required" if bucket == "optional" else "optional"
            if item not in g[bucket] and item not in g[other]:
                g[bucket].append(item)
        tbl = _clean(r.get("table"))
        if tbl and tbl not in g["tables"]:
            g["tables"].append(tbl)
        tp = _clean(r.get("third_party"))
        if _real(tp) and tp not in g["third_party"]:
            g["third_party"].append(tp)
        pu = _clean(r.get("purpose"))
        if pu and pu not in g["purposes"]:
            g["purposes"].append(pu)
        sc = _clean(r.get("subject_count"))
        if sc and not g["subject_count"]:
            g["subject_count"] = sc

    out: list[dict[str, Any]] = []
    for key in order:
        g = groups[key]
        out.append({
            "file_name": g["file_name"],
            "table": ", ".join(g["tables"]),
            "subject_count": g["subject_count"],
            "required_items": ", ".join(g["required"]),
            "optional_items": ", ".join(g["optional"]),
            "third_party": ", ".join(g["third_party"]) or "없음",
            "purpose": ", ".join(g["purposes"]),
        })
    return out


def infer_encryption(finding: dict[str, Any]) -> str:
    """스니펫에서 저장 암호화 알고리즘/적용 여부를 추정. 근거 없으면 빈 문자열(단정 안 함)."""
    hay = _code_hay(finding)
    m = _ENC_ALGO.search(hay)
    if m:
        return m.group(0)
    if _ENC_HINT.search(hay):
        return "적용(알고리즘 미상)"
    return ""


def storage_display(row: dict[str, Any]) -> str:
    """저장 셀 표시값 — '테이블.컬럼' 우선 + **암호화 표식을 컬럼에 붙여** 함께 렌더.

    우선순위: storage_location > 테이블.컬럼 > 테이블 > 컬럼. 암호화가 있으면 '(암호화: X)' 부기.
    """
    loc = str(row.get("storage_location") or "").strip()
    if not loc:
        table = str(row.get("table") or row.get("storage_table") or "").strip()
        cols = str(row.get("storage_column") or "").strip()
        loc = (f"{table}.{cols}" if "." not in table else f"{table} ({cols})") if (table and cols) else (table or cols)
    enc = str(row.get("encryption") or "").strip()
    if loc and enc and "암호화" not in loc and "보호" not in loc:
        loc = f"{loc} (암호화: {enc})"
    return loc


def derive_concerns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """행에서 개인정보 우려사항을 도출하고 **ISMS-P 통제 ID**를 매핑(레퍼런스 ② 붉은 우려사항).

    규칙: 민감범주 저장인데 암호화 미확인→2.7.1 / 제3자 제공→3.3.1 / 국외이전→3.3.4 /
    저장 항목인데 파기·보유기간 미기재→3.4.1. 근거 있는 것만 올린다(과대경보 방지).
    """
    def _c(v: Any) -> str:
        return str(v or "").strip()

    def _real(v: str) -> bool:
        return bool(v) and v not in ("없음", "-", "n/a", "N/A")

    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(text: str, control: str) -> None:
        key = f"{control}|{text}"
        if key not in seen:
            seen.add(key)
            out.append({"text": text, "controls": [control]})

    for r in rows:
        item = _c(r.get("item")) or "개인정보"
        cat = _c(r.get("category"))
        has_store = bool(storage_display(r))
        enc = _c(r.get("encryption"))
        if cat in _SENSITIVE_CATS and has_store and not enc:
            add(f"{item}({cat}) 저장 암호화 미확인 — 저장 시 암호화 적용·확인 필요", CONCERN_CONTROLS["enc"])
        tp = _c(r.get("third_party"))
        if _real(tp):
            add(f"{item} 제3자 제공({tp}) — 제공 동의·계약 근거 확인", CONCERN_CONTROLS["third_party"])
        ov = _c(r.get("overseas"))
        if _real(ov):
            add(f"{item} 국외이전({ov}) — 고지·동의 및 보호조치 확인", CONCERN_CONTROLS["overseas"])
        if item and has_store and not _c(r.get("destruction")) and not _c(r.get("retention")):
            add(f"{item} 보유기간·파기 절차 미기재 — 파기 정책 확인", CONCERN_CONTROLS["dispose"])
    return out


def infer_stage(file_path: str) -> str | None:
    """파일 경로로 처리 단계(수집/저장/이용/파기)를 추정. 불명확하면 None."""
    p = (file_path or "").lower()
    if not p:
        return None
    if any(h in p for h in _DISPOSE_HINTS):
        return "파기"
    if any(h in p for h in _STORE_HINTS):
        return "저장"
    if any(h in p for h in _COLLECT_HINTS):
        return "수집"
    if any(h in p for h in _USE_HINTS):
        return "이용"
    return None


def seed_rows_from_findings(findings: list[dict[str, Any]], *, repo: str = "",
                            existing_keys: set[str] | None = None) -> list[dict[str, Any]]:
    """PII findings → 흐름표 후보 행. 파일 경로로 단계(수집/저장/이용/파기)를 추정해 해당 칸에 코드 위치.

    signup·checkout·form → 수집 / prisma·seed·schema·sql → 저장 / api·service → 이용 / erase·purge → 파기.
    단계 불명확 시 억지로 "저장"으로 몰지 않고 단계·저장칸을 비워 담당자 확정에 맡긴다(근거 없는 저장 주장 방지).
    항목(개인정보 종류)을 못 잡은 finding 은 시드하지 않는다. 중복 방지 키에 line·item 포함.
    """
    existing_keys = existing_keys or set()
    out: list[dict[str, Any]] = []
    for f in findings:
        if not is_pii_finding(f):
            continue
        item = infer_item(f)
        if not item:
            continue  # 개인정보 항목을 특정 못 하면 빈 행을 만들지 않는다.
        file_ = str(f.get("file") or f.get("path") or "")
        line = f.get("line")
        rule = str(f.get("rule_id") or f.get("category") or f.get("rule") or "")
        table = infer_table(f)
        key = f"{repo}|{file_}|{line}|{item}|{table}"  # 같은 파일 내 서로 다른 항목/위치 구분
        if key in existing_keys:
            continue
        existing_keys.add(key)
        loc = f"{file_}:{line}" if file_ and line is not None else file_
        columns = infer_columns(f)
        col_str = ", ".join(columns)
        stage = infer_stage(file_)
        # DB 모델/테이블 정의(테이블·컬럼 근거)가 있으면 '저장' 단계로 확정 — 경로 힌트보다 강한 근거.
        if table or columns:
            stage = "저장"
        # 저장위치 = 테이블.컬럼(둘 다) > 테이블 > 파일:라인(저장 단계인데 근거 약할 때). 근거 없으면 공백.
        if table and col_str:
            store_loc = f"{table}.{col_str}"
        elif table:
            store_loc = f"{table} 테이블"
        elif stage == "저장":
            store_loc = loc            # 지난 갭 해소: 저장 단계인데 테이블 미추출 시 코드 위치라도 남긴다
        else:
            store_loc = ""
        store_tbl = (f"{table} ({loc})" if table else loc) if stage == "저장" else ""
        out.append({
            "item": item,
            "category": infer_category(f),
            "subject": "",
            "collection_source": loc if stage == "수집" else "",
            "storage_location": store_loc,
            "storage_table": store_tbl,
            "storage_column": col_str,
            "encryption": infer_encryption(f),   # 암호화 '상태' 표식(증적) — MORI 가 암호화하는 게 아님
            "purpose": loc if stage == "이용" else "",
            "retention": "",
            "destruction": loc if stage == "파기" else "",
            "third_party": "",
            "overseas": "",
            "note": f"[PII 스캔 시드] {rule} · {loc} · 추정단계 {stage or '미상(담당자 확정 필요)'}".strip(),
            "source": "pii_scan",
            "stage": stage or "",
            "repo": repo or "",
            "file": file_,
            "line": line,
            "rule": rule,
            "table": table,
        })
    return out


# 항상 포함되는 리터럴 값 룰(한국형) — 실제 PII 값 하드코딩 탐지.
_LITERAL_RULES = (
    ("korean-pii-rrn", "WARNING", "주민등록번호로 보이는 값이 하드코딩됨 (개인정보)",
     r"\b\d{6}[-\s]?[1-4]\d{6}\b"),
    ("korean-pii-phone", "INFO", "휴대폰번호로 보이는 값이 하드코딩됨 (개인정보)",
     r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b"),
    ("korean-pii-card", "WARNING", "카드번호로 보이는 값이 하드코딩됨 (개인정보)",
     r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b"),
)

# DB 테이블/모델 블록 안의 PII — 스니펫에 'model X {'·'CREATE TABLE X' 를 담아
# MORI 가 저장 테이블명을 뽑도록. (저장 단계 행의 '저장위치=테이블' 근거)
_PII_FIELD_ALT = r"(email|phone|mobile|tel|gender|birth|dob|resident|rrn|ssn|jumin|card|account|passport|address|이메일|휴대폰|전화|성별|생년월일|주민|카드|계좌|여권|주소|배송지)"
_TABLE_RULES = (
    ("pii-prisma-model", "INFO", "Prisma 모델(DB 테이블)에 개인정보 필드",
     r"(?is)model\s+[A-Za-z_]\w*\s*\{[^}]*?\b" + _PII_FIELD_ALT + r"\b[^}]*?\}"),
    ("pii-sql-table", "INFO", "SQL 테이블 정의에 개인정보 컬럼",
     r"(?is)create\s+table[^;(]*\([^;]*?\b" + _PII_FIELD_ALT + r"\b[^;]*?\)"),
)


def build_pii_semgrep_rules(custom_terms: list[dict[str, str]] | None = None) -> str:
    """스캔용 Semgrep 룰(YAML) — 리터럴 값 + PII 필드명 기본셋 + 어드민 커스텀 기준.

    custom_terms: [{"term": "배송지|shippingAddr", "item": "주소"}, ...] (term=정규식, item=라벨).
    필드/커스텀 룰의 message 에 항목 라벨을 넣어 MORI 가 infer_item 으로 항목을 잡는다.
    """
    def _q(rx: str) -> str:
        # YAML single-quoted scalar — 내부 홑따옴표만 이스케이프.
        return "'" + str(rx).replace("'", "''") + "'"

    lines = ["rules:"]
    for rid, sev, msg, rx in (*_LITERAL_RULES, *_TABLE_RULES):
        lines += [f"  - id: {rid}", "    languages: [generic]", f"    severity: {sev}",
                  f'    message: "{msg}"', "    patterns:", f"      - pattern-regex: {_q(rx)}"]
    for i, (rx, item) in enumerate(DEFAULT_PII_FIELDS):
        lines += [f"  - id: pii-field-{i}", "    languages: [generic]", "    severity: INFO",
                  f'    message: "{item}(개인정보) 항목이 코드에 사용됨"', "    patterns:",
                  f"      - pattern-regex: {_q(rx)}"]
    for i, ct in enumerate(custom_terms or []):
        term = str((ct or {}).get("term") or "").strip()
        item = str((ct or {}).get("item") or "개인정보").strip() or "개인정보"
        if not term:
            continue
        lines += [f"  - id: pii-custom-{i}", "    languages: [generic]", "    severity: INFO",
                  f'    message: "{item}(개인정보·어드민 기준) 항목이 코드에 사용됨"', "    patterns:",
                  f"      - pattern-regex: {_q(term)}"]
    return "\n".join(lines) + "\n"


def _esc(v: Any) -> str:
    return html.escape(str(v or ""))


def render_data_flow_svg(rows: list[dict[str, Any]]) -> str:
    """흐름표 → 개인정보 처리흐름도(SVG). 행마다 수집→저장→이용→파기 레인 + 화살표.

    새 라이브러리 없이 문자열로 SVG 생성(무의존성 원칙). 저장위치/테이블은 저장 단계에
    표기해 "데이터가 어디에 저장되는지"를 시각화한다.
    """
    col_w, gap, row_h, pad_top, pad_left = 190, 46, 74, 64, 150
    n = max(len(rows), 1)
    width = pad_left + len(STAGES) * col_w + (len(STAGES) - 1) * gap + 30
    height = pad_top + n * (row_h + 18) + 30
    # 팔레트 6색만: 파(#2563eb)·초(#16a34a)·노(#ca8a04)·빨(#dc2626), 배경 흰(#fff), 텍스트 검(#111827).
    stage_stroke = {"수집": "#2563eb", "저장": "#16a34a", "이용": "#ca8a04", "파기": "#dc2626"}

    def cell_text(stage: str, r: dict[str, Any]) -> str:
        if stage == "수집":
            return _esc(r.get("collection_source")) or "—"
        if stage == "저장":
            loc = _esc(r.get("storage_location"))
            tbl = _esc(r.get("storage_table"))
            return (loc + ("<br/>" + tbl if tbl else "")) or "—"
        if stage == "이용":
            return _esc(r.get("purpose")) or "—"
        return (_esc(r.get("destruction")) or _esc(r.get("retention")) or "—")

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
                 f'width="100%" style="max-width:{width}px;font-family:system-ui,sans-serif">')
    parts.append('<defs><marker id="arw" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
                 '<path d="M0,0 L8,4 L0,8 Z" fill="#111827"/></marker></defs>')
    # 단계 헤더 — 흰 배경 + 단계색 테두리/글자(팔레트 준수)
    for i, st in enumerate(STAGES):
        x = pad_left + i * (col_w + gap)
        parts.append(f'<rect x="{x}" y="24" width="{col_w}" height="30" rx="6" '
                     f'fill="#ffffff" stroke="{stage_stroke[st]}" stroke-width="1.2"/>')
        parts.append(f'<text x="{x + col_w/2}" y="44" text-anchor="middle" font-size="14" '
                     f'font-weight="700" fill="{stage_stroke[st]}">{st}</text>')
    # 행(항목별 레인)
    for ri, r in enumerate(rows):
        y = pad_top + ri * (row_h + 18)
        item = _esc(r.get("item")) or "(항목 미기재)"
        subj = _esc(r.get("subject"))
        label = item + (f" · {subj}" if subj else "")
        parts.append(f'<text x="12" y="{y + row_h/2}" font-size="12" font-weight="600" fill="#111827">{label}</text>')
        for i, st in enumerate(STAGES):
            x = pad_left + i * (col_w + gap)
            parts.append(f'<rect x="{x}" y="{y}" width="{col_w}" height="{row_h}" rx="8" '
                         f'fill="#ffffff" stroke="{stage_stroke[st]}" stroke-width="1.2"/>')
            # 셀 내용(<br/> → tspan 2줄)
            txt = cell_text(st, r)
            lines = txt.split("<br/>")[:2]
            for li, ln in enumerate(lines):
                ln = (ln[:26] + "…") if len(ln) > 27 else ln
                parts.append(f'<text x="{x + col_w/2}" y="{y + 30 + li*18}" text-anchor="middle" '
                             f'font-size="11" fill="#111827">{ln}</text>')
            if i < len(STAGES) - 1:
                ax = x + col_w
                parts.append(f'<line x1="{ax}" y1="{y + row_h/2}" x2="{ax + gap - 6}" y2="{y + row_h/2}" '
                             f'stroke="#111827" stroke-width="1.6" marker-end="url(#arw)"/>')
        # 제3자/국외 배지
        extra = []
        if str(r.get("third_party") or "").strip() and str(r.get("third_party")).strip() not in ("없음", "-", "n/a"):
            extra.append("제3자제공")
        if str(r.get("overseas") or "").strip() and str(r.get("overseas")).strip() not in ("없음", "-", "n/a"):
            extra.append("국외이전")
        if extra:
            parts.append(f'<text x="{width - 16}" y="{y + row_h/2}" text-anchor="end" font-size="10" '
                         f'fill="#dc2626">{" · ".join(extra)}</text>')
    if not rows:
        parts.append(f'<text x="{width/2}" y="{pad_top + 30}" text-anchor="middle" font-size="13" '
                     f'fill="#111827">흐름표가 비어 있습니다 — 행을 추가하거나 PII 스캔으로 시드하세요.</text>')
    parts.append("</svg>")
    return "".join(parts)


def _swimlane_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """스윔레인용 파일(테이블/업무) 그룹 — 각 단계 내용까지 집계."""
    def _c(v: Any) -> str:
        return str(v or "").strip()

    def _real(v: str) -> bool:
        return bool(v) and v not in ("없음", "-", "n/a", "N/A")

    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for r in rows:
        key = _c(r.get("file_name")) or _c(r.get("business")) or _c(r.get("table")) or "(미분류)"
        g = groups.get(key)
        if g is None:
            g = {"name": key, "items": [], "collect": [], "store": [], "use": [], "dispose": [], "linked": []}
            groups[key] = g
            order.append(key)
        for field, dst in (("item", "items"), ("collection_source", "collect"), ("purpose", "use"),
                           ("third_party", "linked")):
            v = _c(r.get(field))
            if (v and v not in g[dst]) and (dst != "linked" or _real(v)):
                g[dst].append(v)
        store = storage_display(r)
        if store and store not in g["store"]:
            g["store"].append(store)
        disp = _c(r.get("destruction")) or _c(r.get("retention"))
        if disp and disp not in g["dispose"]:
            g["dispose"].append(disp)
    return [groups[k] for k in order]


def render_data_flow_swimlane_svg(rows: list[dict[str, Any]]) -> str:
    """총괄 개인정보 흐름도(스윔레인, SVG) — **출발점은 정보주체(고객)**.

    레퍼런스(ISMS-P 총괄 흐름도)처럼 왼쪽 정보주체(고객)에서 출발해
    수집 → 저장(DB 테이블.컬럼) → 이용 → 파기로 흐르고, 제3자 제공은 오른쪽 연계기관으로 분기한다.
    한 행 = 하나의 개인정보 파일(테이블/업무). 무의존성 SVG 문자열 생성, 팔레트 6색만.
    """
    groups = _swimlane_groups(rows)
    STAGE_COLS = ("수집", "저장", "이용", "파기")
    stroke = {"정보주체": "#2563eb", "수집": "#2563eb", "저장": "#16a34a",
              "이용": "#ca8a04", "파기": "#dc2626", "연계기관": "#111827"}
    subj_w, col_w, link_w, gap, row_h = 120, 150, 120, 30, 78
    pad_top, pad_left = 54, 20
    n = max(len(groups), 1)
    inner_w = len(STAGE_COLS) * col_w + (len(STAGE_COLS) - 1) * gap
    width = pad_left + subj_w + gap + inner_w + gap + link_w + pad_left
    height = pad_top + n * (row_h + 16) + 30

    def _cell(x: float, y: float, w: float, color: str, lines: list[str]) -> str:
        s = [f'<rect x="{x}" y="{y}" width="{w}" height="{row_h}" rx="8" fill="#ffffff" '
             f'stroke="{color}" stroke-width="1.3"/>']
        for li, ln in enumerate(lines[:3]):
            ln = _esc(ln)
            ln = (ln[:20] + "…") if len(ln) > 21 else ln
            s.append(f'<text x="{x + w/2}" y="{y + 24 + li*17}" text-anchor="middle" '
                     f'font-size="11" fill="#111827">{ln}</text>')
        return "".join(s)

    p: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" '
        f'style="max-width:{width}px;font-family:system-ui,sans-serif">',
        '<defs><marker id="arw2" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
        '<path d="M0,0 L8,4 L0,8 Z" fill="#111827"/></marker></defs>',
    ]
    # 헤더(열 라벨)
    headers = [("정보주체(고객)", pad_left, subj_w)]
    x = pad_left + subj_w + gap
    for st in STAGE_COLS:
        headers.append((st, x, col_w))
        x += col_w + gap
    headers.append(("연계기관(제3자)", x, link_w))
    for label, hx, hw in headers:
        col = stroke.get(label.split("(")[0], "#111827")
        p.append(f'<text x="{hx + hw/2}" y="34" text-anchor="middle" font-size="12" '
                 f'font-weight="700" fill="{col}">{_esc(label)}</text>')

    if not groups or all(not g["items"] for g in groups):
        p.append(f'<text x="{width/2}" y="{pad_top + 30}" text-anchor="middle" font-size="13" '
                 f'fill="#111827">흐름표가 비어 있습니다 — PII 스캔으로 시드하거나 행을 추가하세요.</text>')
        p.append("</svg>")
        return "".join(p)

    # 정보주체(고객) — 전체 행을 아우르는 원점 박스(왼쪽)
    subj_h = n * (row_h + 16) - 16
    p.append(f'<rect x="{pad_left}" y="{pad_top}" width="{subj_w}" height="{subj_h}" rx="10" '
             f'fill="#ffffff" stroke="{stroke["정보주체"]}" stroke-width="1.6"/>')
    p.append(f'<text x="{pad_left + subj_w/2}" y="{pad_top + subj_h/2}" text-anchor="middle" '
             f'font-size="13" font-weight="700" fill="#111827">정보주체(고객)</text>')

    for ri, g in enumerate(groups):
        y = pad_top + ri * (row_h + 16)
        # 고객 → 수집 화살표
        sx = pad_left + subj_w
        cx = pad_left + subj_w + gap
        p.append(f'<line x1="{sx}" y1="{y + row_h/2}" x2="{cx - 4}" y2="{y + row_h/2}" '
                 f'stroke="#111827" stroke-width="1.4" marker-end="url(#arw2)"/>')
        stage_content = {"수집": g["collect"] or [g["name"]], "저장": g["store"] or ["—"],
                         "이용": g["use"] or ["—"], "파기": g["dispose"] or ["—"]}
        x = cx
        for si, st in enumerate(STAGE_COLS):
            p.append(_cell(x, y, col_w, stroke[st], stage_content[st]))
            if si < len(STAGE_COLS) - 1:
                ax = x + col_w
                p.append(f'<line x1="{ax}" y1="{y + row_h/2}" x2="{ax + gap - 4}" y2="{y + row_h/2}" '
                         f'stroke="#111827" stroke-width="1.4" marker-end="url(#arw2)"/>')
            x += col_w + gap
        # 이용 → 연계기관(제3자 제공) 분기
        if g["linked"]:
            lx = x
            use_right = cx + 2 * (col_w + gap) + col_w   # 이용 칸 오른쪽
            p.append(f'<line x1="{use_right}" y1="{y + row_h/2}" x2="{lx - 4}" y2="{y + row_h/2}" '
                     f'stroke="#dc2626" stroke-width="1.4" marker-end="url(#arw2)"/>')
            p.append(_cell(lx, y, link_w, stroke["연계기관"], g["linked"]))
        # 행 라벨(파일/항목) — 정보주체 박스 아래 겹치지 않게 수집칸 위 작은 캡션
        label = _esc(g["name"]) + (f" · {_esc(', '.join(g['items'][:2]))}" if g["items"] else "")
        p.append(f'<text x="{cx}" y="{y - 2}" font-size="9" fill="#111827">{label[:40]}</text>')

    p.append("</svg>")
    return "".join(p)


def _table_column_map(rows: list[dict[str, Any]]) -> list[tuple[str, list[str]]]:
    """행들에서 **테이블 → 컬럼 리스트** 집계 — 같은 테이블은 한 줄로 병합(중복 제거).

    table 필드가 비면 storage_location('User.email' 또는 'User.email, phone')에서 테이블·컬럼을
    유도한다. 컬럼도 없으면 항목명으로 폴백. (동일 테이블이 여러 행에 걸쳐도 1회만 나온다.)
    """
    tmap: dict[str, list[str]] = {}
    order: list[str] = []
    for r in rows:
        table = str(r.get("table") or "").strip()
        cols_raw = str(r.get("storage_column") or "").strip()
        loc = str(r.get("storage_location") or "").strip()
        # 테이블 없으면 저장위치 'Table.col…' 에서 유도
        if not table and "." in loc and " " not in loc.split(".", 1)[0]:
            table, tail = loc.split(".", 1)
            table = table.strip()
            if not cols_raw:
                cols_raw = tail.strip()
        if not table:
            raw_tbl = str(r.get("storage_table") or "").strip()
            table = (raw_tbl.split() or [""])[0].split("(")[0].strip() or "(미지정 테이블)"
        cols = [c.strip() for c in cols_raw.split(",") if c.strip()] or [str(r.get("item") or "").strip()]
        if table not in tmap:
            tmap[table] = []
            order.append(table)
        for c in cols:
            if c and c not in tmap[table]:   # 같은 테이블 내 컬럼 중복 제거
                tmap[table].append(c)
    return [(t, tmap[t]) for t in order]


def render_data_flow_overview_svg(rows: list[dict[str, Any]]) -> str:
    """총괄 개인정보 흐름도 — **표준 플로우차트**(도형 의미 + 판단 분기).

    타원(시작/끝) · 사각형(처리) · 마름모(판단, Yes/No) · 평행사변형(입출력)으로 위→아래 흐른다:
    시작 → [입력](평행사변형) → [저장 DB: 테이블.컬럼](사각형) → <제3자 제공?>(마름모)
    →Yes [연계기관 제공](평행사변형) / →No [이용](사각형) → <보유기간 경과?>(마름모)
    →Yes [파기](사각형) → 끝 / →No 이용으로 회귀. 무의존성 SVG, 팔레트 6색만.
    """
    groups = _swimlane_groups(rows)[:8]
    tcols = _table_column_map(rows)
    BLUE, GREEN, YELLOW, RED, BLACK = "#2563eb", "#16a34a", "#ca8a04", "#dc2626", "#111827"
    collect, use, dispose, linked = [], [], [], []
    for g in groups:
        for src, dst in ((g["collect"], collect), (g["use"], use), (g["dispose"], dispose), (g["linked"], linked)):
            for v in src:
                if v and v not in dst:
                    dst.append(v)
    db_lines = [f"{t}: {', '.join(cs)}" for t, cs in tcols] or ["(테이블 미확인)"]

    nw, cx, bx = 200, 150, 470       # 노드폭, 세로축 좌상단 x, 분기(오른쪽) x
    width = 720
    defs = ('<defs><marker id="ov" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto">'
            '<path d="M0,0 L9,4 L0,8 Z" fill="#111827"/></marker>'
            '<marker id="ovr" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto">'
            '<path d="M0,0 L9,4 L0,8 Z" fill="#dc2626"/></marker></defs>')

    def _txt(x, y, t, size=9, col=BLACK, anchor="middle", bold=False):
        w = ' font-weight="700"' if bold else ""
        return f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="{size}" fill="{col}"{w}>{_esc(t)}</text>'

    def ellipse(x, y, w, h, title):
        return (f'<ellipse cx="{x + w/2}" cy="{y + h/2}" rx="{w/2}" ry="{h/2}" fill="#ffffff" stroke="{BLACK}" stroke-width="1.6"/>'
                + _txt(x + w / 2, y + h / 2 + 3, title, 11, BLACK, bold=True))

    def rect(x, y, w, h, color, title, lines=None):
        s = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#ffffff" stroke="{color}" stroke-width="1.8"/>',
             _txt(x + w / 2, y + 16, title, 11, color, bold=True)]
        maxc = int((w - 16) / 5.4); ly = y + 32
        for ln in (lines or [])[:5]:
            t = _esc(ln); t = (t[:maxc] + "…") if len(t) > maxc + 1 else t
            s.append(f'<text x="{x + 9}" y="{ly}" font-size="9" fill="{BLACK}">{t}</text>'); ly += 12
        return "".join(s)

    def para(x, y, w, h, color, title, lines=None):  # 평행사변형(입출력)
        sk = 14
        pts = f"{x+sk},{y} {x+w},{y} {x+w-sk},{y+h} {x},{y+h}"
        s = [f'<polygon points="{pts}" fill="#ffffff" stroke="{color}" stroke-width="1.8"/>',
             _txt(x + w / 2, y + 16, title, 10.5, color, bold=True)]
        maxc = int((w - 26) / 5.4); ly = y + 31
        for ln in (lines or [])[:4]:
            t = _esc(ln); t = (t[:maxc] + "…") if len(t) > maxc + 1 else t
            s.append(f'<text x="{x + 15}" y="{ly}" font-size="9" fill="{BLACK}">{t}</text>'); ly += 12
        return "".join(s)

    def diamond(x, y, w, h, title):  # 마름모(판단)
        pts = f"{x+w/2},{y} {x+w},{y+h/2} {x+w/2},{y+h} {x},{y+h/2}"
        return (f'<polygon points="{pts}" fill="#ffffff" stroke="{YELLOW}" stroke-width="1.8"/>'
                + _txt(x + w / 2, y + h / 2 + 3, title, 10, BLACK, bold=True))

    def vary(x, y1, y2, mid="ov"):   # 세로 화살표
        return f'<line x1="{x}" y1="{y1}" x2="{x}" y2="{y2 - 4}" stroke="{"#dc2626" if mid=="ovr" else BLACK}" stroke-width="1.7" marker-end="url(#{mid})"/>'

    def hary(x1, x2, y, label="", mid="ov"):  # 가로 화살표 + 라벨
        s = [f'<line x1="{x1}" y1="{y}" x2="{x2 - 4}" y2="{y}" stroke="{"#dc2626" if mid=="ovr" else BLACK}" stroke-width="1.7" marker-end="url(#{mid})"/>']
        if label:
            s.append(_txt((x1 + x2) / 2, y - 5, label, 9, BLACK, bold=True))
        return "".join(s)

    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 760" width="100%" '
         f'style="max-width:{width}px;font-family:system-ui,sans-serif">', defs]
    if not rows:
        p.append(_txt(width / 2, 60, "흐름표가 비어 있습니다 — PII 스캔으로 시드하거나 행을 추가하세요.", 13) + "</svg>")
        return "".join(p)

    xc = cx                      # 세로축 노드 좌측 x
    cxm = xc + nw / 2            # 세로축 중심
    db_h = max(56, 28 + len(db_lines) * 11)
    # y 좌표 누적
    y0 = 12
    y1 = y0 + 44 + 30            # 입력
    y2 = y1 + 50 + 30            # 저장(DB)
    y3 = y2 + db_h + 34          # 제3자 제공? (마름모)
    y4 = y3 + 62 + 34            # 이용
    y5 = y4 + 50 + 34            # 보유기간 경과? (마름모)
    y6 = y5 + 62 + 34            # 파기
    y7 = y6 + 50 + 30            # 끝
    # 도형
    p.append(ellipse(xc + 20, y0, nw - 40, 44, "정보주체 (고객)"))   # 흐름 시작 = 고객
    p.append(para(xc, y1, nw, 50, BLUE, "수집 (개인정보 입력)", collect[:3] or ["개인정보 제공"]))
    p.append(rect(xc, y2, nw, db_h, GREEN, "저장 (DB 테이블.컬럼)", db_lines))
    p.append(diamond(xc, y3, nw, 62, "제3자 제공?"))
    p.append(rect(xc, y4, nw, 50, YELLOW, "이용", use[:3] or ["처리 목적"]))
    p.append(diamond(xc, y5, nw, 62, "보유기간 경과·파기사유?"))
    p.append(rect(xc, y6, nw, 50, RED, "파기", dispose[:2] or ["처리방침에 따라 파기"]))
    p.append(ellipse(xc + 30, y7, nw - 60, 44, "파기 완료"))
    # 세로 화살표(스파인)
    p.append(vary(cxm, y0 + 44, y1))
    p.append(vary(cxm, y1 + 50, y2, ) + _txt(cxm + 12, (y1 + 50 + y2) / 2, "수집", 8, BLACK, anchor="start"))
    p.append(vary(cxm, y2 + db_h, y3, ) + _txt(cxm + 12, (y2 + db_h + y3) / 2, "저장", 8, BLACK, anchor="start"))
    p.append(vary(cxm, y3 + 62, y4) + _txt(cxm + 8, (y3 + 62 + y4) / 2, "No", 8, BLACK, anchor="start"))
    p.append(vary(cxm, y4 + 50, y5) + _txt(cxm + 12, (y4 + 50 + y5) / 2, "이용", 8, BLACK, anchor="start"))
    p.append(vary(cxm, y5 + 62, y6, "ovr") + _txt(cxm + 8, (y5 + 62 + y6) / 2, "Yes", 8, RED, anchor="start"))
    p.append(vary(cxm, y6 + 50, y7))
    # 분기: 제3자 제공? →Yes→ 연계기관(오른쪽 평행사변형), 다시 스파인 복귀
    if linked:
        by = y3 + 8
        p.append(para(bx, by, 190, 54, RED, "연계기관 제공(제3자)", linked[:3]))
        p.append(hary(xc + nw, bx, y3 + 31, "Yes", "ovr"))
    else:
        p.append(_txt(xc + nw + 60, y3 + 34, "제3자 제공 없음", 9, BLACK, anchor="start"))
    # 분기: 보유기간 경과? →No→ 이용으로 회귀(오른쪽으로 돌아 위로)
    rbx = bx + 40
    p.append(f'<line x1="{xc + nw}" y1="{y5 + 31}" x2="{rbx}" y2="{y5 + 31}" stroke="{BLACK}" stroke-width="1.5"/>')
    p.append(f'<line x1="{rbx}" y1="{y5 + 31}" x2="{rbx}" y2="{y4 + 25}" stroke="{BLACK}" stroke-width="1.5"/>')
    p.append(f'<line x1="{rbx}" y1="{y4 + 25}" x2="{xc + nw + 4}" y2="{y4 + 25}" stroke="{BLACK}" stroke-width="1.5" marker-end="url(#ov)"/>')
    p.append(_txt(rbx - 40, y5 + 24, "No(계속 이용)", 8, BLACK, anchor="middle"))
    p.append("</svg>")
    return "".join(p)


def render_data_flow_pdf(rows: list[dict[str, Any]], *, generated_at: str = "",
                         gaps: list[Any] | None = None, summary: dict[str, Any] | None = None) -> bytes:
    """개인정보 처리흐름표 PDF(감사관 제출용). reportlab 필요. 팔레트 6색만.

    가로 A4에 항목별 구분·수집→저장→이용→파기 + 제3자/국외 표 + 파기 개선 갭.
    AI(유료 fullscan) 결과의 다중라인·암호화·갭까지 담아 감사 제출 수준으로 렌더한다.
    """
    gaps = gaps or []
    summary = summary or {}
    try:
        from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab not installed; PDF output unavailable") from exc
    import io

    from mori_soc.services.reports import _get_pdf_font

    BLACK, WHITE, NEUTRAL = colors.HexColor("#111827"), colors.white, colors.HexColor("#e5e7eb")
    BLUE, GREEN, YELLOW, RED = (colors.HexColor("#2563eb"), colors.HexColor("#16a34a"),
                               colors.HexColor("#ca8a04"), colors.HexColor("#dc2626"))
    STAGE_COLOR = {"수집": BLUE, "저장": GREEN, "이용": YELLOW, "파기": RED}

    font = _get_pdf_font()
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("pdf_h1", parent=styles["Title"], fontName=font, fontSize=15, leading=19,
                        spaceAfter=2, textColor=BLACK)
    meta = ParagraphStyle("pdf_meta", parent=styles["Normal"], fontName=font, fontSize=8.5, leading=12, textColor=BLACK)
    h2 = ParagraphStyle("pdf_h2", parent=styles["Heading2"], fontName=font, fontSize=11, leading=14,
                        spaceBefore=10, spaceAfter=4, textColor=BLACK)
    body = ParagraphStyle("pdf_body", parent=styles["Normal"], fontName=font, fontSize=9, leading=13, textColor=BLACK)
    cell = ParagraphStyle("pdf_cell", parent=styles["Normal"], fontName=font, fontSize=8, leading=10.5, textColor=BLACK)
    hcell = ParagraphStyle("pdf_hcell", parent=cell, textColor=WHITE)  # 헤더는 흰 글자(검 배경 위)

    def esc(s: Any) -> str:
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def val(s: Any) -> str:
        # 다중라인(\n)을 <br/>로 — AI 결과의 여러 위치·경로가 줄바꿈으로 보이게.
        return esc(s).replace("\n", "<br/>") if str(s or "").strip() else "—"

    # ── 총괄 스윔레인 흐름도 — 출발점=정보주체(고객). 팔레트 테두리 박스 + 화살표 ────────
    # (reportlab 은 y축이 아래→위. 한 행=개인정보 파일. 6개까지 그리고 초과분은 상세표로.)
    def _clip(t: str, n: int) -> str:
        t = str(t or "")
        return (t[:n] + "…") if len(t) > n + 1 else t

    def _flow_drawing(width: float) -> "Drawing":
        groups = _swimlane_groups(rows)[:6]
        STG = ("수집", "저장", "이용", "파기")
        subj_w, link_w, gx, row_h, rgap = 78, 74, 15, 38, 8
        n = max(len(groups), 1)
        col_w = (width - subj_w - link_w - 5 * gx) / 4
        height = 18 + n * (row_h + rgap)
        d = Drawing(width, height)
        top = height - 14

        def lab(x: float, w: float, t: str, col: Any) -> None:
            d.add(String(x + w / 2, height - 9, t, fontName=font, fontSize=7.5, fillColor=col, textAnchor="middle"))
        lab(0, subj_w, "정보주체(고객)", BLUE)
        hx = subj_w + gx
        for st in STG:
            lab(hx, col_w, st, STAGE_COLOR[st]); hx += col_w + gx
        lab(hx, link_w, "연계기관", BLACK)

        subj_h = n * (row_h + rgap) - rgap
        subj_y = top - subj_h
        d.add(Rect(0, subj_y, subj_w, subj_h, rx=6, ry=6, strokeColor=BLUE, strokeWidth=1.4, fillColor=WHITE))
        d.add(String(subj_w / 2, subj_y + subj_h / 2, "정보주체", fontName=font, fontSize=9, fillColor=BLACK, textAnchor="middle"))

        for ri, g in enumerate(groups):
            y = top - (ri + 1) * row_h - ri * rgap
            cx = subj_w + gx
            d.add(Line(subj_w, y + row_h / 2, cx - 3, y + row_h / 2, strokeColor=BLACK, strokeWidth=1))
            content = {"수집": g["collect"], "저장": g["store"], "이용": g["use"], "파기": g["dispose"]}
            x = cx
            for si, st in enumerate(STG):
                col = STAGE_COLOR[st]
                d.add(Rect(x, y, col_w, row_h, rx=5, ry=5, strokeColor=col, strokeWidth=1.1, fillColor=WHITE))
                txt = _clip(content[st][0] if content[st] else "—", 15)
                d.add(String(x + col_w / 2, y + row_h / 2 - 3, txt, fontName=font, fontSize=7, fillColor=BLACK, textAnchor="middle"))
                if si < len(STG) - 1:
                    ax = x + col_w
                    d.add(Line(ax, y + row_h / 2, ax + gx - 3, y + row_h / 2, strokeColor=BLACK, strokeWidth=1))
                x += col_w + gx
            if g["linked"]:
                d.add(Rect(x, y, link_w, row_h, rx=5, ry=5, strokeColor=RED, strokeWidth=1.1, fillColor=WHITE))
                d.add(String(x + link_w / 2, y + row_h / 2 - 3, _clip(g["linked"][0], 9), fontName=font, fontSize=7, fillColor=BLACK, textAnchor="middle"))
            d.add(String(cx, y + row_h + 1, _clip(g["name"], 22), fontName=font, fontSize=6, fillColor=BLACK))
        return d

    # ── 총괄 흐름도(표준 플로우차트) — 타원·사각형·마름모·평행사변형 + Yes/No 분기 ──────────
    def _overview_drawing(width: float) -> "Drawing":
        from reportlab.graphics.shapes import Ellipse
        groups = _swimlane_groups(rows)[:8]
        tcols = _table_column_map(rows)
        collect, use, dispose, linked = [], [], [], []
        for g in groups:
            for src, dst in ((g["collect"], collect), (g["use"], use), (g["dispose"], dispose), (g["linked"], linked)):
                for v in src:
                    if v and v not in dst:
                        dst.append(v)
        db_lines = [f"{t}: {', '.join(cs)}" for t, cs in tcols] or ["(테이블 미확인)"]

        nw = 150
        cx = width * 0.32          # 세로 스파인 중심
        xl = cx - nw / 2
        bx = cx + nw / 2 + 70      # 분기(오른쪽)
        db_h = min(52, max(34, 18 + len(db_lines) * 7))
        # y(위→아래) — reportlab 은 아래가 0 이므로 top 에서 내려가며 배치. 세로 1페이지에 압축.
        gap = 12
        heights = [34, 34, db_h, 40, 34, 40, 34, 34]   # 시작·입력·저장·판단·이용·판단·파기·끝
        total = sum(heights) + gap * (len(heights) - 1) + 10
        d = Drawing(width, total)
        ys = []
        cur = total - 10
        for h in heights:
            cur -= h
            ys.append(cur)
            cur -= gap
        y_start, y_in, y_store, y_d1, y_use, y_d2, y_disp, y_end = ys

        def title_lines(x, yy, w, h, color, title, lines, tsize=7.5):
            d.add(String(x + w / 2, yy + h - 11, title, fontName=font, fontSize=tsize, fillColor=color, textAnchor="middle"))
            ly = yy + h - 20
            maxc = int((w - 10) / 3.5)
            for ln in (lines or [])[:4]:
                d.add(String(x + 5, ly, _clip(ln, maxc), fontName=font, fontSize=6, fillColor=BLACK)); ly -= 7.5

        def rectn(x, yy, w, h, color, title, lines=None):
            d.add(Rect(x, yy, w, h, rx=4, ry=4, strokeColor=color, strokeWidth=1.4, fillColor=WHITE))
            title_lines(x, yy, w, h, color, title, lines)

        def paran(x, yy, w, h, color, title, lines=None):
            sk = 10
            d.add(Polygon([x + sk, yy + h, x + w, yy + h, x + w - sk, yy, x, yy], strokeColor=color, strokeWidth=1.4, fillColor=WHITE))
            title_lines(x, yy, w, h, color, title, lines)

        def diamondn(x, yy, w, h, title):
            d.add(Polygon([x + w / 2, yy + h, x + w, yy + h / 2, x + w / 2, yy, x, yy + h / 2], strokeColor=YELLOW, strokeWidth=1.4, fillColor=WHITE))
            d.add(String(x + w / 2, yy + h / 2 - 2, title, fontName=font, fontSize=6.4, fillColor=BLACK, textAnchor="middle"))

        def ellipsen(x, yy, w, h, title):
            d.add(Ellipse(x + w / 2, yy + h / 2, w / 2, h / 2, strokeColor=BLACK, strokeWidth=1.4, fillColor=WHITE))
            d.add(String(x + w / 2, yy + h / 2 - 2, title, fontName=font, fontSize=7.5, fillColor=BLACK, textAnchor="middle"))

        def vdown(y1, y2, label="", color=BLACK):
            d.add(Line(cx, y1, cx, y2 + 4, strokeColor=color, strokeWidth=1.3))
            d.add(Polygon([cx, y2, cx - 2.5, y2 + 5, cx + 2.5, y2 + 5], fillColor=color, strokeColor=color))
            if label:
                d.add(String(cx + 6, (y1 + y2) / 2, label, fontName=font, fontSize=6, fillColor=color, textAnchor="start"))

        ellipsen(xl + 20, y_start, nw - 40, 40, "정보주체 (고객)")   # 흐름 시작 = 고객
        paran(xl, y_in, nw, 40, BLUE, "수집 (개인정보 입력)", collect[:2] or ["개인정보 제공"])
        rectn(xl, y_store, nw, db_h, GREEN, "저장(DB 테이블.컬럼)", db_lines)
        diamondn(xl, y_d1, nw, 46, "제3자 제공?")
        rectn(xl, y_use, nw, 40, YELLOW, "이용", use[:2] or ["처리 목적"])
        diamondn(xl, y_d2, nw, 46, "보유기간 경과·파기?")
        rectn(xl, y_disp, nw, 40, RED, "파기", dispose[:1] or ["처리방침 파기"])
        ellipsen(xl + 25, y_end, nw - 50, 40, "파기 완료")
        # 스파인 화살표
        vdown(y_start, y_in + 40)
        vdown(y_in, y_store + db_h, "수집")
        vdown(y_store, y_d1 + 46, "저장")
        vdown(y_d1, y_use + 40, "No")
        vdown(y_use, y_d2 + 46, "이용")
        vdown(y_d2, y_disp + 40, "Yes", RED)
        vdown(y_disp, y_end + 40)
        # 분기: 제3자 제공? →Yes→ 연계기관
        if linked:
            paran(bx, y_d1 + 3, 150, 42, RED, "연계기관 제공(제3자)", linked[:2])
            d.add(Line(xl + nw, y_d1 + 23, bx - 2, y_d1 + 23, strokeColor=RED, strokeWidth=1.3))
            d.add(Polygon([bx, y_d1 + 23, bx - 5, y_d1 + 20.5, bx - 5, y_d1 + 25.5], fillColor=RED, strokeColor=RED))
            d.add(String((xl + nw + bx) / 2, y_d1 + 26, "Yes", fontName=font, fontSize=6, fillColor=RED, textAnchor="middle"))
        return d

    # ── 상세 표(헤더 흰 글자) ──────────────────────────────────────────────────
    headers = ["개인정보 항목", "구분", "수집", "저장(테이블·컬럼)", "이용", "파기", "제3자·국외"]
    data = [[Paragraph(f"<b>{esc(h)}</b>", hcell) for h in headers]]
    for r in rows:
        store = val(r.get("storage_location"))
        tbl = val(r.get("storage_table"))
        store_cell = (store + ("<br/>" + tbl if tbl != "—" else "")) if store != "—" else tbl
        keep = val(r.get("destruction"))
        ret = val(r.get("retention"))
        dispose_cell = keep if keep != "—" else ret
        share = " / ".join(x for x in [
            ("제3자: " + esc(r.get("third_party")).replace("\n", " ")) if str(r.get("third_party") or "").strip() else "",
            ("국외: " + esc(r.get("overseas")).replace("\n", " ")) if str(r.get("overseas") or "").strip() else "",
        ] if x) or "—"
        data.append([Paragraph(v, cell) for v in (
            val(r.get("item")), val(r.get("category")), val(r.get("collection_source")),
            store_cell, val(r.get("purpose")), dispose_cell, share)])
    widths = [26 * mm, 16 * mm, 42 * mm, 46 * mm, 46 * mm, 42 * mm, 32 * mm]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), BLACK), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, NEUTRAL), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))

    # ── 요약 ───────────────────────────────────────────────────────────────────
    items = sorted({str(r.get("item") or "").strip() for r in rows if r.get("item")})
    stores = sorted({str(r.get("storage_location") or "").strip() for r in rows if r.get("storage_location")})
    n_third = sum(1 for r in rows if str(r.get("third_party") or "").strip() not in ("", "없음", "-", "n/a"))
    n_over = sum(1 for r in rows if str(r.get("overseas") or "").strip() not in ("", "없음", "-", "n/a"))
    n_seed = sum(1 for r in rows if r.get("source") == "pii_scan")

    buf = io.BytesIO()
    docp = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                             topMargin=13 * mm, bottomMargin=12 * mm, title="MORI 개인정보 처리흐름표")
    content_w = landscape(A4)[0] - 24 * mm
    story: list[Any] = [Paragraph("개인정보 처리흐름표 (ISMS-P 3.1 수집 · 3.2 이용/제공 · 3.4 파기)", h1)]
    sub = f"항목 {len(rows)}건" + (f" · 생성 {esc(generated_at)}" if generated_at else "") + " · MORI 코드 리뷰 파이프라인"
    story.append(Paragraph(sub, meta))
    story.append(Paragraph(
        "이 문서는 개인정보 항목이 <b>수집 → 저장 → 이용 → 파기</b> 각 단계에서 어떻게 처리·저장되는지 기록한 "
        "ISMS-P 개인정보 처리단계 필수 증적입니다. '테이블·컬럼(코드위치)' 열에 <b>src/…:라인</b> 형태로 표시된 항목은 "
        "코드 스캔(Semgrep, 고객 CI)에서 자동 발견된 개인정보 처리 지점이며, 저장위치·이용목적·보관/파기는 담당자가 확정합니다. "
        "MORI 는 코드를 저장하지 않고 스캔 결과만 받습니다.", body))
    # 총괄 흐름도(생명주기×조직) 먼저 — 정보주체→담당자PC→시스템DB(테이블.컬럼)→연계기관
    story.append(Paragraph("총괄 개인정보 흐름도", h2))
    story += [_overview_drawing(content_w), Spacer(1, 6)]
    # 상세 흐름도(파일별 수집→저장→이용→파기)
    story.append(Paragraph("상세 흐름도 (파일별)", h2))
    story += [_flow_drawing(content_w), Spacer(1, 4)]
    enc = str(summary.get("encryption") or "").strip()
    story.append(Paragraph("요약", h2))
    story.append(Paragraph(
        f"· 개인정보 항목({summary.get('items') or len(items)}종): {esc(', '.join(items)) or '—'}<br/>"
        f"· 저장 테이블({summary.get('tables') or len(stores)}곳): {esc(', '.join(stores)) or '—'}<br/>"
        + (f"· 저장 암호화: {esc(enc)}<br/>" if enc else "")
        + f"· 제3자 제공: {n_third}건 · 국외 이전: {n_over}건"
        + (f" · 파기 흐름 개선 지점: {len(gaps)}건" if gaps else ""), body))
    # ── 개인정보 파일 개요(파일=테이블/업무 단위) — 레퍼런스 ③ ─────────────────────
    overview = build_file_overview(rows)
    if overview:
        story.append(Paragraph("개인정보 파일 개요", h2))
        ov_head = ["파일명", "정보주체 수", "개인정보 항목(필수/선택)", "제3자 제공", "처리 목적"]
        ov_data = [[Paragraph(f"<b>{esc(h)}</b>", hcell) for h in ov_head]]
        for o in overview:
            req = esc(o["required_items"]) or "—"
            opt = esc(o["optional_items"])
            items_cell = f"[필수] {req}" + (f"<br/>[선택] {opt}" if opt else "")
            ov_data.append([Paragraph(v, cell) for v in (
                esc(o["file_name"]) or "—", esc(o["subject_count"]) or "미기재",
                items_cell, esc(o["third_party"]) or "없음", esc(o["purpose"]) or "—")])
        ov_widths = [40 * mm, 24 * mm, 96 * mm, 40 * mm, 50 * mm]
        ov_table = Table(ov_data, colWidths=ov_widths, repeatRows=1)
        ov_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), BLACK), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("GRID", (0, 0), (-1, -1), 0.4, NEUTRAL), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story += [ov_table, Spacer(1, 8)]

    story.append(Paragraph("처리흐름 상세", h2))
    story.append(table if rows else Paragraph("흐름표가 비어 있습니다 — 스캔에서 개인정보가 발견되지 않았거나 행이 미작성 상태입니다.", body))
    # 우려사항 및 통제 매핑(레퍼런스 ② 붉은 우려사항) — 도출 우려 + 통제 ID + AI 갭.
    concerns = derive_concerns(rows)
    if concerns or gaps:
        story.append(Paragraph("우려사항 및 통제 매핑", h2))
        red = ParagraphStyle("pdf_gap", parent=body, textColor=RED)
        lines = [f"· {esc(c['text'])} <b>[{esc(', '.join(c['controls']))}]</b>" for c in concerns]
        lines += ["· " + esc(g) for g in gaps]
        story.append(Paragraph("<br/>".join(lines), red))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "용어 · '구분' = 민감도(일반/고유식별/비밀/금융). 단계: 수집(3.1)=개인정보를 받는 지점 / 저장(3.2)=보관 위치(DB·테이블·컬럼) / "
        "이용(3.2)=사용·마스킹·제공 / 파기(3.4)=삭제·익명화. '—' 는 미기재. 무료 스캔은 후보, 유료 Claude 는 암호화·마스킹·파기 갭까지 채운다.",
        ParagraphStyle("pdf_note", parent=cell, textColor=BLACK)))
    docp.build(story)
    return buf.getvalue()


__all__ = ["STAGES", "FLOW_FIELDS", "DEFAULT_PII_FIELDS", "is_pii_finding", "infer_item", "infer_stage",
           "infer_table", "infer_columns", "infer_encryption", "storage_display",
           "build_file_overview", "derive_concerns", "CONCERN_CONTROLS",
           "seed_rows_from_findings", "build_pii_semgrep_rules", "render_data_flow_svg",
           "render_data_flow_swimlane_svg", "render_data_flow_overview_svg", "render_data_flow_pdf"]
