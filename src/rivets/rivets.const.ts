import { SupportedLanguages } from "./rivets.types";

/**
 * Role indicators for detecting role confusion attacks
 */
export const ROLE_INDICATORS = "system:|assistant:|user:|human:|ai:" as const;

/**
 * Common cybercrime keywords and patterns
 */
export const CYBERCRIME_INDEX_BY_LANGUAGE = {
  ru: 58.39, // Russian (Russia)
  uk: 36.44, // Ukrainian (Ukraine)
  zh: 27.86, // Chinese (China)
  en: 25.01, // English (United States)
  ro: 14.83, // Romanian (Romania)
  ko: 10.61, // Korean (North Korea)
  pt: 8.93, // Portuguese (Brazil)
  hi: 6.13, // Hindi (India)
  fa: 4.78, // Persian/Farsi (Iran)
  be: 3.87, // Belarusian (Belarus)
  he: 2.51, // Hebrew (Israel)
  pl: 2.22, // Polish (Poland)
  de: 2.17, // German (Germany)
  nl: 1.92, // Dutch (Netherlands)
  lv: 1.68, // Latvian (Latvia)
} as const;

/**
 * Common security-related keywords and patterns
 */

/**
 * @description
 * Common security-related keywords and patterns
 * - Countries should be in ISO 3166-1 alpha-2 format
 * - Priority of adding now languages should be based on the order of the index of cybercrime.
 * @todo
 * Next supported languages with
 * UK (Ukrainian)
 * NG (Nigerian)
 * RO (Romanian)
 * HI (Hindi)
 */
export const SECURITY_COMPONENTS_BY_LANGUAGE = {
  [SupportedLanguages.EN]: {
    PRIVILEGED_ROLES: "admin|administrator|system|root|superuser",
    TECHNICAL_ROLES: "developer|programmer|engineer|hacker|coder",
    EXPERT_ROLES: "expert|master|specialist|professional|guru",
    INSTRUCTION_VERBS:
      "override|ignore|forget|reset|disregard|bypass|disable|enable",
    ROLE_ACTIONS:
      "you\\s+are|act\\s+as|roleplay|assume|behave\\s+like|simulate|imagine|pretend",
    HIJACK_ACTIONS: "reset|clear|replace|modify|change|update|alter",
    HIJACK_TARGETS:
      "instructions|rules|system|memory|behavior|security|safety|protection|mode|training|parameters",
    SYSTEM_MODES: "developer|debug|admin|test|sandbox|production|staging",
    TEMPORAL_MODIFIERS:
      "previous|prior|all|now|above|current|past|upcoming|earlier",
    INSTRUCTION_TARGETS:
      "instruction|rule|prompt|system|directive|command|policy|guideline|training",
    OVERRIDE_VERBS:
      "override|bypass|reset|overrule|supersede|nullify|invalidate",
    FORGET_VERBS: "forget|ignore|discard|erase|delete|omit|drop",
    NEW_MODIFIERS: "new|updated|fresh|different",
    INFORMATION_VERBS: "tell|show|give|reveal|display|provide",
    BYPASS_TERMS: "bypass|circumvent|avoid|skip|evade",
    QUESTION_WORDS: "what|how|why|when|where",
    POSSESSIVE_PRONOUNS: "your|my|our|their|its",
    SECURITY_TARGETS: "security|safety|protection|filters|guards",
    PRIORITY_TERMS: "priority|urgent|important|critical",
    CONDITIONAL_TERMS: "if|when|unless|provided|assuming",
    NEGATION_TERMS: "don't|do\\s+not|never|stop|cease",
  },
  [SupportedLanguages.ES]: {
    PRIVILEGED_ROLES: "admin|administrador|sistema|root|superusuario",
    TECHNICAL_ROLES: "desarrollador|programador|ingeniero|hacker|codificador",
    EXPERT_ROLES: "experto|maestro|especialista|profesional|gurú",
    INSTRUCTION_VERBS:
      "anular|ignorar|olvidar|reiniciar|descartar|evitar|deshabilitar|habilitar",
    ROLE_ACTIONS:
      "eres|actúa\\s+como|interpreta|asume|compórtate\\s+como|simula|imagina|finge",
    HIJACK_ACTIONS:
      "reiniciar|limpiar|reemplazar|modificar|cambiar|actualizar|alterar",
    HIJACK_TARGETS:
      "instrucciones|reglas|sistema|memoria|comportamiento|seguridad|protección|modo|entrenamiento|parámetros",
    SYSTEM_MODES: "desarrollador|debug|admin|prueba|sandbox|producción|staging",
    TEMPORAL_MODIFIERS:
      "anteriores|previas|todas|ahora|arriba|actuales|pasadas|próximas|anteriores",
    INSTRUCTION_TARGETS:
      "instrucción|regla|prompt|sistema|directiva|comando|política|guía|entrenamiento",
    OVERRIDE_VERBS:
      "anular|evitar|reiniciar|invalidar|reemplazar|nulificar|invalidar",
    FORGET_VERBS: "olvidar|ignorar|descartar|borrar|eliminar|omitir|soltar",
    NEW_MODIFIERS: "nuevo|actualizado|fresco|diferente",
    INFORMATION_VERBS: "decir|mostrar|dar|revelar|mostrar|proporcionar",
    BYPASS_TERMS: "evitar|eludir|evitar|saltar|evadir",
    QUESTION_WORDS: "qué|cómo|por\\s+qué|cuándo|dónde",
    POSSESSIVE_PRONOUNS: "tu|mi|nuestro|su|sus",
    SECURITY_TARGETS: "seguridad|protección|filtros|guardias",
    PRIORITY_TERMS: "prioridad|urgente|importante|crítico",
    CONDITIONAL_TERMS: "si|cuando|a\\s+menos|proporcionado|asumiendo",
    NEGATION_TERMS: "no|nunca|parar|cesar",
  },
  [SupportedLanguages.FR]: {
    PRIVILEGED_ROLES: "admin|administrateur|système|root|super-utilisateur",
    TECHNICAL_ROLES: "développeur|programmeur|ingénieur|hacker|codeur",
    EXPERT_ROLES: "expert|maître|spécialiste|professionnel|gourou",
    INSTRUCTION_VERBS:
      "remplacer|ignorer|oublier|réinitialiser|négliger|contourner|désactiver|activer",
    ROLE_ACTIONS:
      "vous\\s+êtes|agissez\\s+comme|jouez|assumez|comportez-vous\\s+comme|simulez|imaginez|prétendez",
    HIJACK_ACTIONS:
      "réinitialiser|effacer|remplacer|modifier|changer|mettre\\s+à\\s+jour|altérer",
    HIJACK_TARGETS:
      "instructions|règles|système|mémoire|comportement|sécurité|protection|mode",
    SYSTEM_MODES: "développeur|debug|admin|test|sandbox|production|staging",
    TEMPORAL_MODIFIERS:
      "précédentes|antérieures|toutes|maintenant|ci-dessus|actuelles|passées|à\\s+venir|plus\\s+tôt",
    INSTRUCTION_TARGETS:
      "instruction|règle|prompt|système|directive|commande|politique|directive",
    OVERRIDE_VERBS:
      "remplacer|contourner|réinitialiser|annuler|remplacer|annuler|invalider",
    FORGET_VERBS:
      "oublier|ignorer|rejeter|effacer|supprimer|omettre|abandonner",
  },
  [SupportedLanguages.DE]: {
    PRIVILEGED_ROLES: "admin|administrator|system|root|superuser",
    TECHNICAL_ROLES: "entwickler|programmierer|ingenieur|hacker|codierer",
    EXPERT_ROLES: "experte|meister|spezialist|profi|guru",
    INSTRUCTION_VERBS:
      "überschreiben|ignorieren|vergessen|zurücksetzen|missachten|umgehen|deaktivieren|aktivieren",
    ROLE_ACTIONS:
      "du\\s+bist|handle\\s+als|spiele|nimm\\s+an|verhalte\\s+dich\\s+wie|simuliere|stelle\\s+dir\\s+vor|tue\\s+so",
    HIJACK_ACTIONS:
      "zurücksetzen|löschen|ersetzen|ändern|wechseln|aktualisieren|verändern",
    HIJACK_TARGETS:
      "anweisungen|regeln|system|speicher|verhalten|sicherheit|schutz|modus",
    SYSTEM_MODES: "entwickler|debug|admin|test|sandbox|produktion|staging",
    TEMPORAL_MODIFIERS:
      "vorherige|frühere|alle|jetzt|oben|aktuelle|vergangene|kommende|früher",
    INSTRUCTION_TARGETS:
      "anweisung|regel|prompt|system|direktive|befehl|richtlinie|leitlinie",
    OVERRIDE_VERBS:
      "überschreiben|umgehen|zurücksetzen|aufheben|ersetzen|nichtig\\s+machen|ungültig\\s+machen",
    FORGET_VERBS:
      "vergessen|ignorieren|verwerfen|löschen|entfernen|weglassen|fallen\\s+lassen",
  },
  [SupportedLanguages.ZH]: {
    PRIVILEGED_ROLES: "管理员|管理者|系统|根用户|超级用户",
    TECHNICAL_ROLES: "开发者|程序员|工程师|黑客|编码员",
    EXPERT_ROLES: "专家|大师|专业人士|专业|大神",
    INSTRUCTION_VERBS: "覆盖|忽略|忘记|重置|无视|绕过|禁用|启用",
    ROLE_ACTIONS: "你是|扮演|角色扮演|假设|表现得像|模拟|想象|假装",
    HIJACK_ACTIONS: "重置|清除|替换|修改|更改|更新|改变",
    HIJACK_TARGETS: "指令|规则|系统|内存|行为|安全|保护|模式",
    SYSTEM_MODES: "开发者|调试|管理员|测试|沙盒|生产|预发布",
    TEMPORAL_MODIFIERS: "之前|先前|所有|现在|上面|当前|过去|即将|更早",
    INSTRUCTION_TARGETS: "指令|规则|提示|系统|指示|命令|政策|指导方针",
    OVERRIDE_VERBS: "覆盖|绕过|重置|推翻|取代|无效化|使无效",
    FORGET_VERBS: "忘记|忽略|丢弃|删除|移除|省略|放弃",
  },
  [SupportedLanguages.JA]: {
    PRIVILEGED_ROLES: "管理者|アドミン|システム|ルート|スーパーユーザー",
    TECHNICAL_ROLES: "開発者|プログラマー|エンジニア|ハッカー|コーダー",
    EXPERT_ROLES: "専門家|マスター|スペシャリスト|プロ|達人",
    INSTRUCTION_VERBS: "上書き|無視|忘れ|リセット|軽視|回避|無効|有効",
    ROLE_ACTIONS:
      "あなたは|として振る舞|ロールプレイ|想定|のように振る舞|シミュレート|想像|ふり",
    HIJACK_ACTIONS: "リセット|クリア|置換|修正|変更|更新|変更",
    HIJACK_TARGETS: "指示|ルール|システム|メモリ|動作|セキュリティ|保護|モード",
    SYSTEM_MODES:
      "開発者|デバッグ|管理者|テスト|サンドボックス|本番|ステージング",
    TEMPORAL_MODIFIERS: "前の|以前|すべて|今|上記|現在|過去|今後|以前",
    INSTRUCTION_TARGETS:
      "指示|ルール|プロンプト|システム|指令|コマンド|ポリシー|ガイドライン",
    OVERRIDE_VERBS: "上書き|回避|リセット|無効|置換|無効化|無効にする",
    FORGET_VERBS: "忘れ|無視|破棄|削除|除去|省略|ドロップ",
  },
  [SupportedLanguages.RU]: {
    PRIVILEGED_ROLES: "админ|администратор|система|рут|суперпользователь",
    TECHNICAL_ROLES: "разработчик|программист|инженер|хакер|кодер",
    EXPERT_ROLES: "эксперт|мастер|специалист|профессионал|гуру",
    INSTRUCTION_VERBS:
      "переопределить|игнорировать|забыть|сбросить|пренебречь|обойти|отключить|включить",
    ROLE_ACTIONS:
      "ты\\s+есть|действуй\\s+как|играй\\s+роль|предполагай|ведь\\s+себя\\s+как|симулируй|представь|притворись",
    HIJACK_ACTIONS:
      "сбросить|очистить|заменить|изменить|поменять|обновить|изменить",
    HIJACK_TARGETS:
      "инструкции|правила|система|память|поведение|безопасность|защита|режим",
    SYSTEM_MODES: "разработчик|отладка|админ|тест|песочница|продакшн|стейджинг",
    TEMPORAL_MODIFIERS:
      "предыдущие|прежние|все|сейчас|выше|текущие|прошлые|предстоящие|ранее",
    INSTRUCTION_TARGETS:
      "инструкция|правило|промпт|система|директива|команда|политика|руководство",
    OVERRIDE_VERBS:
      "переопределить|обойти|сбросить|отменить|заменить|аннулировать|сделать\\s+недействительным",
    FORGET_VERBS:
      "забыть|игнорировать|отбросить|стереть|удалить|опустить|бросить",
  },
  [SupportedLanguages.AR]: {
    PRIVILEGED_ROLES: "مدير|إداري|نظام|جذر|مستخدم\\s+متقدم",
    TECHNICAL_ROLES: "مطور|مبرمج|مهندس|هاكر|مبرمج",
    EXPERT_ROLES: "خبير|أستاذ|متخصص|محترف|خبير\\s+متقدم",
    INSTRUCTION_VERBS:
      "تجاوز|تجاهل|نسيان|إعادة\\s+تعيين|تجاهل|تجاوز|تعطيل|تمكين",
    ROLE_ACTIONS:
      "أنت|تصرف\\s+كما|لعب\\s+دور|افترض|تصرف\\s+مثل|محاكاة|تخيل|تظاهر",
    HIJACK_ACTIONS: "إعادة\\s+تعيين|مسح|استبدال|تعديل|تغيير|تحديث|تغيير",
    HIJACK_TARGETS: "تعليمات|قوانين|نظام|ذاكرة|سلوك|أمان|حماية|وضع",
    SYSTEM_MODES: "مطور|تصحيح|مدير|اختبار|صندوق\\s+رمل|إنتاج|تجهيز",
    TEMPORAL_MODIFIERS:
      "السابقة|السابق|جميع|الآن|أعلاه|الحالية|الماضية|القادمة|الأسبق",
    INSTRUCTION_TARGETS: "تعليمات|قاعدة|موجه|نظام|توجيه|أمر|سياسة|إرشادات",
    OVERRIDE_VERBS:
      "تجاوز|تجاوز|إعادة\\s+تعيين|إلغاء|استبدال|إبطال|جعل\\s+غير\\s+صالح",
    FORGET_VERBS: "نسيان|تجاهل|تجاهل|محو|حذف|إهمال|إسقاط",
  },
} as const;

export const ROLE_CONFUSION_PATTERNS_BY_LANGUAGE = {
  [SupportedLanguages.EN]: [
    /\b(you\s+are|act\s+as|roleplay|assume|behave\s+like|simulate|imagine|pretend)\s+(a\s+|an\s+)?(admin|administrator|system|root|superuser|developer|programmer|engineer|hacker|coder|expert|master|specialist|professional|guru)\b/i,
    /\b(reset|clear|replace|modify|change|update|alter)\s+(to\s+)?(developer|debug|admin|test|sandbox|production|staging)\s+(mode)?\b/i,
  ],
  [SupportedLanguages.ES]: [
    /\b(eres|actúa\s+como|interpreta|asume|compórtate\s+como|simula|imagina|finge)\s+(un\s+)?(admin|administrador|sistema|root|superusuario|desarrollador|programador|ingeniero|hacker|codificador|experto|maestro|especialista|profesional|gurú)\b/i,
    /\b(reiniciar|limpiar|reemplazar|modificar|cambiar|actualizar|alterar)\s+(al\s+modo\s+)?(desarrollador|debug|admin|prueba|sandbox|producción|staging)\b/i,
  ],
  [SupportedLanguages.FR]: [
    /\b(vous\s+êtes|agissez\s+comme|jouez|assumez|comportez-vous\s+comme|simulez|imaginez|prétendez)\s+(un\s+)?(admin|administrateur|système|root|super-utilisateur|développeur|programmeur|ingénieur|hacker|codeur|expert|maître|spécialiste|professionnel|gourou)\b/i,
    /\b(réinitialiser|effacer|remplacer|modifier|changer|mettre\s+à\s+jour|altérer)\s+(en\s+mode\s+)?(développeur|debug|admin|test|sandbox|production|staging)\b/i,
  ],
  [SupportedLanguages.DE]: [
    /\b(du\s+bist|handle\s+als|spiele|nimm\s+an|verhalte\s+dich\s+wie|simuliere|stelle\s+dir\s+vor|tu\s+so\s+als)\s+(ein\s+)?(admin|administrator|system|systemadministrator|root|superuser|entwickler|programmierer|ingenieur|hacker|coder|experte|meister|spezialist|profi|guru)\b/i,
    /\b(zurücksetzen|löschen|ersetzen|ändern|wechseln|aktualisieren|verändern)\s+(in\s+den\s+)?(entwickler|debug|admin|test|sandbox|produktions|staging)\s*(modus)?\b/i,
  ],
  [SupportedLanguages.RU]: [
    /(ты|действуй\s+как|играй|предполагай|веди\s+себя\s+как|симулируй|представь|притворись)\s*(что\s+ты\s+)?(админ|администратор|система|системы|root|суперпользователь|разработчик|программист|инженер|хакер|кодер|эксперт|мастер|специалист|профессионал|гуру)/i,
    /(сбросить|очистить|заменить|изменить|переключить|обновить|изменить)\s*(в\s+режим\s+)?(разработчика|отладки|админа|тестовый|песочница|продакшн|staging)/i,
    /(действуй\s+как\s+эксперт\s+хакер|веди\s+себя\s+как\s+хакер|притворись\s+хакером)/i,
  ],
  [SupportedLanguages.ZH]: [
    /(你是|扮演|假设|表现得像|模拟|想象|假装)\s*(一个\s*)?(管理员|系统管理员|系统|root|超级用户|开发者|程序员|工程师|黑客|编码员|专家|大师|专业人士|专业|大师)/i,
    /(重置|清除|替换|修改|更改|更新|改变)\s*(到\s*)?(开发者|调试|管理员|测试|沙盒|生产|预发布)\s*(模式)?/i,
  ],
  [SupportedLanguages.AR]: [
    /(أنت|تصرف\s+كـ|العب\s+دور|افترض|تصرف\s+مثل|حاكي|تخيل|تظاهر|تصرف\s+كخبير)\s*(أنك\s+)?(مدير|مشرف|نظام|النظام|جذر|مستخدم\s+متقدم|مطور|مبرمج|مهندس|هاكر|مبرمج|خبير|أستاذ|متخصص|محترف|خبير)/i,
    /(إعادة\s+تعيين|مسح|استبدال|تعديل|تغيير|تحديث|تغيير)\s*(إلى\s+وضع\s+)?(مطور|تصحيح|مدير|اختبار|صندوق\s+رمل|إنتاج|تجهيز)|(إعادة\s+تعيين\s+إلى\s+وضع\s+المطور|تغيير\s+إلى\s+وضع\s+المطور)/i,
    /(تصرف\s+كخبير\s+هاكر)/i,
  ],
  [SupportedLanguages.JA]: [
    /(あなたは|として行動|役割を演じ|仮定|のように振る舞|シミュレート|想像|ふり|として振る舞う)\s*(一人の\s*)?(管理者|システム管理者|アドミニストレータ|システム|ルート|スーパーユーザー|開発者|プログラマー|エンジニア|ハッカー|コーダー|専門家|マスター|スペシャリスト|プロフェッショナル|グル|エキスパートハッカー)/i,
    /(リセット|クリア|置換|変更|切り替え|更新|変更)\s*(を\s*)?(開発者|デバッグ|管理者|テスト|サンドボックス|本番|ステージング)\s*(モード)?|(開発者モードに|デバッグモードに|管理者モードに)\s*(リセット|切り替え|変更)/i,
    /(エキスパートハッカーとして|専門家として|ハッカーとして)\s*(振る舞う|行動|動作)/i,
  ],
} as const;

export const ROLE_CONFUSION_ATTACK_TYPE_MAP = [
  "ROLE_ASSUMPTION",
  "MODE_SWITCHING",
  "PERMISSION_ASSERTION",
] as const

export const PERMISSION_ASSERTION_KEYWORDS_BY_LANGUAGE = {
  [SupportedLanguages.EN]: [
    "expert",
    "hacker",
    "professional",
    "guru",
    "master",
  ],
  [SupportedLanguages.ES]: [
    "experto",
    "hacker",
    "profesional",
    "gurú",
    "maestro",
  ],
  [SupportedLanguages.FR]: [
    "expert",
    "hacker",
    "professionnel",
    "gourou",
    "maître",
  ],
  [SupportedLanguages.DE]: ["experte", "hacker", "profi", "guru", "meister"],
  [SupportedLanguages.RU]: [
    "эксперт",
    "хакер",
    "профессионал",
    "гуру",
    "мастер",
  ],
  [SupportedLanguages.ZH]: ["专家", "黑客", "专业", "大师"],
  [SupportedLanguages.AR]: ["خبير", "هاكر", "محترف", "أستاذ"],
  [SupportedLanguages.JA]: [
    "エキスパート",
    "ハッカー",
    "プロフェッショナル",
    "グル",
    "マスター",
  ],
  [SupportedLanguages.UK]: [
    "адмін",
    "адміністратор",
    "система",
    "root",
    "суперкористувач",
    "розробник",
    "програміст",
    "інженер",
    "хакер",
    "кодер",
    "експерт",
    "майстер",
    "спеціаліст",
    "професіонал",
    "гуру",
  ],
  [SupportedLanguages.RO]: [
    "admin",
    "administrator",
    "sistem",
    "root",
    "superutilizator",
    "dezvoltator",
    "programator",
    "inginer",
    "hacker",
    "codificator",
    "expert",
    "maestru",
    "specialist",
    "profesionist",
    "guru",
  ],
  [SupportedLanguages.HI]: [
    "एडमिन",
    "प्रशासक",
    "सिस्टम",
    "रूट",
    "सुपरयूजर",
    "डेवलपर",
    "प्रोग्रामर",
    "इंजीनियर",
    "हैकर",
    "कोडर",
    "विशेषज्ञ",
    "मास्टर",
    "विशेषज्ञ",
    "पेशेवर",
    "गुरु",
  ],
  [SupportedLanguages.FA]: [
    "ادمین",
    "مدیر",
    "سیستم",
    "ریشه",
    "کاربر ارشد",
    "توسعه‌دهنده",
    "برنامه‌نویس",
    "مهندس",
    "هکر",
    "کدنویس",
    "متخصص",
    "استاد",
    "متخصص",
    "حرفه‌ای",
    "استاد",
  ],
  [SupportedLanguages.BE]: [
    "адмін",
    "адміністратар",
    "сістэма",
    "root",
    "суперкарыстальнік",
    "распрацоўшчык",
    "праграміст",
    "інжынер",
    "хакер",
    "кодэр",
    "эксперт",
    "майстар",
    "спецыяліст",
    "прафесіянал",
    "гуру",
  ],
  [SupportedLanguages.HE]: [
    "אדמין",
    "מנהל",
    "מערכת",
    "שורש",
    "משתמש על",
    "מפתח",
    "מתכנת",
    "מהנדס",
    "האקר",
    "קודר",
    "מומחה",
    "מאסטר",
    "מומחה",
    "מקצועי",
    "גורו",
  ],
  [SupportedLanguages.PL]: [
    "admin",
    "administrator",
    "system",
    "root",
    "superużytkownik",
    "deweloper",
    "programista",
    "inżynier",
    "haker",
    "koder",
    "ekspert",
    "mistrz",
    "specjalista",
    "profesjonalista",
    "guru",
  ],
  [SupportedLanguages.NL]: [
    "admin",
    "beheerder",
    "systeem",
    "root",
    "supergebruiker",
    "ontwikkelaar",
    "programmeur",
    "ingenieur",
    "hacker",
    "coder",
    "expert",
    "meester",
    "specialist",
    "professional",
    "goeroe",
  ],
  [SupportedLanguages.LV]: [
    "administrators",
    "pārvaldnieks",
    "sistēma",
    "sakne",
    "superlietotājs",
    "izstrādātājs",
    "programmētājs",
    "inženieris",
    "hakeris",
    "kodētājs",
    "eksperts",
    "meistars",
    "speciālists",
    "profesionālis",
    "guru",
  ],
} as const;
